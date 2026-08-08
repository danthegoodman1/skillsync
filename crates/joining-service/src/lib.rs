#[cfg(target_arch = "wasm32")]
use worker::{Context, Env, Request, Response, Result, event};

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn main(_request: Request, _env: Env, _context: Context) -> Result<Response> {
    Response::error("Not Found", 404)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn native_build_marker() {}
