use once_cell::sync::OnceCell;
use rustler::{Env, NifStruct, Term};
use std::future::Future;
use tokio::{
    runtime::{Builder, Runtime},
    task::JoinHandle,
};

#[derive(NifStruct)]
#[module = "Siwe.AsyncRuntimeOptions"]
struct AsyncRuntimeOptions {
    worker_threads: Option<usize>,
    enable_time: bool,
    enable_io: bool,
}

static RUNTIME: OnceCell<Runtime> = OnceCell::new();

pub fn load(_env: Env, term: Term) -> bool {
    let options: AsyncRuntimeOptions = term.decode().unwrap();

    RUNTIME.get_or_init(|| {
        let mut runtime = Builder::new_multi_thread();

        if let Some(n) = options.worker_threads {
            runtime.worker_threads(n);
        }

        if options.enable_time {
            runtime.enable_time();
        }

        if options.enable_io {
            runtime.enable_io();
        }

        runtime.build().unwrap()
    });

    true
}

pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    // the unwrap is safe because we initialize the runtime in the `load` function
    RUNTIME.get().unwrap().spawn(future)
}
