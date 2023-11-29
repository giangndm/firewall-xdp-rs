use aya_bpf::{programs::{XdpContext, TcContext}, bindings::TC_ACT_PIPE};
use core::mem;

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

#[inline(always)]
pub unsafe fn tc_ptr_at(ctx: &TcContext, offset: usize, buf: &mut [u8]) -> Result<(), i32> {
    if ctx.len() >= (offset + buf.len()) as u32 {
        let len = ctx.load_bytes(offset, buf).map_err(|_| TC_ACT_PIPE)?;
        if len == buf.len() {
            Ok(())
        } else {
            Err(TC_ACT_PIPE)
        }
    } else {
        Err(TC_ACT_PIPE)
    }
}