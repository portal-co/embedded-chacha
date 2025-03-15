#![no_std]

use core::slice;

use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, generic_array::GenericArray},
};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct ChaCha<T, C = ChaCha20> {
    pub wrapped: T,
    pub read: C,
    pub write: C,
}
impl<T: embedded_io::ErrorType, C> embedded_io::ErrorType for ChaCha<T, C> {
    type Error = T::Error;
}
impl<T: embedded_io::Read, C: StreamCipher> embedded_io::Read for ChaCha<T, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let a = self.wrapped.read(buf)?;
        self.read.apply_keystream(&mut buf[..a]);
        Ok(a)
    }
}
impl<T: embedded_io_async::Read, C: StreamCipher> embedded_io_async::Read for ChaCha<T, C> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let a = self.wrapped.read(buf).await?;
        self.read.apply_keystream(&mut buf[..a]);
        Ok(a)
    }
}
impl<T: embedded_io::Write, C: StreamCipherSeek + StreamCipher> embedded_io::Write
    for ChaCha<T, C>
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut i = 0;
        for b in buf.iter() {
            let mut c = 0u8;
            let _ = self
                .write
                .apply_keystream_b2b(slice::from_ref(b), slice::from_mut(&mut c));
            let d = self.wrapped.write(slice::from_ref(&c))?;
            if d == 0 {
                let cur: usize = self.write.current_pos::<usize>() - 1;
                self.write.seek(cur);
                return Ok(i);
            }
        }
        Ok(i)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.wrapped.flush()
    }
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Self::Error> {
        for b in buf.iter() {
            let mut c = 0u8;
            let _ = self
                .write
                .apply_keystream_b2b(slice::from_ref(b), slice::from_mut(&mut c));
            self.wrapped.write_all(slice::from_ref(&c))?;
        }
        Ok(())
    }
}
impl<T: embedded_io_async::Write, C: StreamCipherSeek + StreamCipher> embedded_io_async::Write
    for ChaCha<T, C>
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut i = 0;
        for b in buf.iter() {
            let mut c = 0u8;
            let _ = self
                .write
                .apply_keystream_b2b(slice::from_ref(b), slice::from_mut(&mut c));
            let d = self.wrapped.write(slice::from_ref(&c)).await?;
            if d == 0 {
                let cur: usize = self.write.current_pos::<usize>() - 1;
                self.write.seek(cur);
                return Ok(i);
            }
        }
        Ok(i)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.wrapped.flush().await
    }

    async fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Self::Error> {
        for b in buf.iter() {
            let mut c = 0u8;
            let _ = self
                .write
                .apply_keystream_b2b(slice::from_ref(b), slice::from_mut(&mut c));
            self.wrapped.write_all(slice::from_ref(&c)).await?;
        }
        Ok(())
    }
}
impl<T, C: KeyIvInit> ChaCha<T, C> {
    pub fn new(
        wrapped: T,
        key: &GenericArray<u8, C::KeySize>,
        iv: GenericArray<u8, C::IvSize>,
    ) -> Self {
        let mut iv2 = iv.clone();
        for i in iv2.iter_mut() {
            *i ^= 0xff;
        }
        Self {
            wrapped,
            read: C::new(key, &iv),
            write: C::new(key, &iv2),
        }
    }
}
