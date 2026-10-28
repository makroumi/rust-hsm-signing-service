//! Bounded session pool with authenticated, reusable PKCS#11 sessions.

use crate::config::Pkcs11Config;
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    error::{Error as CkError, RvError},
    session::{Session, UserType},
    types::AuthPin,
};
use hsm_core::{HsmError, HsmResult};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit};
use tracing::{debug, info, warn};

/// Pool of pre-authenticated PKCS#11 sessions.
///
/// Sessions are *not* dropped between requests; instead they are returned
/// to the pool for reuse. This is critical because `C_Login` on `SoftHSM`
/// takes ~ms and would dominate signing latency otherwise.
pub struct SessionPool {
    _ctx: Arc<Pkcs11>,
    cfg: Pkcs11Config,
    sessions: Mutex<Vec<Session>>,
    permits: Arc<Semaphore>,
    size: usize,
}

impl SessionPool {
    /// Initialize the pool.
    pub async fn new(cfg: Pkcs11Config) -> HsmResult<Self> {
        let module = cfg.module_path.clone();
        let slot_id = cfg.slot_id;
        let pin = cfg.user_pin.clone();
        let size = cfg.pool_size.max(1);

        let (ctx, sessions) = tokio::task::spawn_blocking(move || -> HsmResult<_> {
            let ctx = Pkcs11::new(&module).map_err(|e| HsmError::Backend(Box::new(e)))?;
            ctx.initialize(CInitializeArgs::OsThreads)
                .map_err(|e| HsmError::Backend(Box::new(e)))?;

            let slot = ctx
                .get_slots_with_token()
                .map_err(|e| HsmError::Backend(Box::new(e)))?
                .into_iter()
                .find(|s| s.id() == slot_id)
                .ok_or_else(|| HsmError::Unavailable(format!("slot {slot_id} not found")))?;

            let mut sessions = Vec::with_capacity(size);
            for i in 0..size {
                let sess = ctx
                    .open_rw_session(slot)
                    .map_err(|e| HsmError::Backend(Box::new(e)))?;
                let login_result =
                    sess.login(UserType::User, Some(&AuthPin::new(pin.as_str().to_owned())));
                match login_result {
                    // Success or already-logged-in (per-token state) are both fine.
                    Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                    Err(CkError::Pkcs11(RvError::PinIncorrect | RvError::PinLocked, _)) => {
                        return Err(HsmError::AuthenticationFailed);
                    }
                    Err(other) => return Err(HsmError::Backend(Box::new(other))),
                }
                debug!(idx = i, "pkcs11 session opened & authenticated");
                sessions.push(sess);
            }
            Ok((Arc::new(ctx), sessions))
        })
        .await
        .map_err(|e| HsmError::Backend(Box::new(e)))??;

        info!(
            pool_size = size,
            slot_id, "PKCS#11 session pool initialized"
        );

        Ok(Self {
            _ctx: ctx,
            cfg,
            sessions: Mutex::new(sessions),
            permits: Arc::new(Semaphore::new(size)),
            size,
        })
    }

    /// Pool capacity.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Approximate number of in-flight (checked-out) sessions.
    pub fn in_flight(&self) -> usize {
        self.size - self.permits.available_permits()
    }

    /// Acquire a session asynchronously, respecting the configured timeout.
    pub async fn acquire(&self) -> HsmResult<PooledSession<'_>> {
        let permit = tokio::time::timeout(self.cfg.acquire_timeout, self.permits.acquire())
            .await
            .map_err(|_| {
                warn!("session acquire timed out");
                HsmError::PoolExhausted
            })?
            .map_err(|_| HsmError::Unavailable("semaphore closed".into()))?;
        let sess = self
            .sessions
            .lock()
            .pop()
            .ok_or_else(|| HsmError::Unavailable("pool desynced".into()))?;
        Ok(PooledSession {
            session: Some(sess),
            pool: self,
            _permit: permit,
        })
    }

    /// Blocking variant used inside `spawn_blocking` contexts.
    pub fn blocking_acquire(self: &Arc<Self>) -> HsmResult<PooledSessionOwned> {
        let start = Instant::now();
        let permit = loop {
            if let Ok(p) = self.permits.clone().try_acquire_owned() {
                break p;
            }
            if start.elapsed() >= self.cfg.acquire_timeout {
                warn!("blocking session acquire timed out");
                return Err(HsmError::PoolExhausted);
            }
            std::thread::sleep(Duration::from_micros(200));
        };
        let sess = self
            .sessions
            .lock()
            .pop()
            .ok_or_else(|| HsmError::Unavailable("pool desynced".into()))?;
        Ok(PooledSessionOwned {
            session: Some(sess),
            pool: self.clone(),
            _permit: permit,
        })
    }

    fn release(&self, session: Session) {
        self.sessions.lock().push(session);
    }
}

/// RAII guard for an async-acquired session.
pub struct PooledSession<'a> {
    session: Option<Session>,
    pool: &'a SessionPool,
    _permit: SemaphorePermit<'a>,
}

impl PooledSession<'_> {
    /// Access the underlying session.
    pub fn session(&self) -> &Session {
        self.session.as_ref().expect("session present")
    }
}

impl Drop for PooledSession<'_> {
    fn drop(&mut self) {
        if let Some(s) = self.session.take() {
            self.pool.release(s);
        }
    }
}

/// Owned variant used from blocking contexts.
pub struct PooledSessionOwned {
    session: Option<Session>,
    pool: Arc<SessionPool>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PooledSessionOwned {
    /// Access the underlying session.
    pub fn session(&self) -> &Session {
        self.session.as_ref().expect("session present")
    }
}

impl Drop for PooledSessionOwned {
    fn drop(&mut self) {
        if let Some(s) = self.session.take() {
            self.pool.release(s);
        }
    }
}
