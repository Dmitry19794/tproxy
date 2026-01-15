use std::os::unix::io::{AsRawFd, RawFd};
use std::io::{self, Error, ErrorKind};
use libc::{c_void, off_t, size_t, ssize_t};

const SPLICE_SIZE: usize = 65536;
const SENDFILE_SIZE: usize = 65536;

pub struct ZeroCopyTransfer {
    buffer_size: usize,
}

impl ZeroCopyTransfer {
    pub fn new(buffer_size: usize) -> Self {
        Self { buffer_size }
    }

    pub async fn splice_bidirectional<R, W>(
        &self,
        read_fd: RawFd,
        write_fd: RawFd,
    ) -> io::Result<u64>
    where
        R: AsRawFd,
        W: AsRawFd,
    {
        let mut total_transferred = 0u64;
        
        loop {
            let transferred = self.splice_once(read_fd, write_fd)?;
            
            if transferred == 0 {
                break;
            }
            
            total_transferred += transferred as u64;
        }
        
        Ok(total_transferred)
    }

    fn splice_once(&self, fd_in: RawFd, fd_out: RawFd) -> io::Result<ssize_t> {
        let result = unsafe {
            libc::splice(
                fd_in,
                std::ptr::null_mut(),
                fd_out,
                std::ptr::null_mut(),
                self.buffer_size,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };

        if result < 0 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(err);
        }

        Ok(result)
    }

    pub fn sendfile(&self, out_fd: RawFd, in_fd: RawFd, offset: Option<off_t>, count: size_t) -> io::Result<ssize_t> {
        let mut off = offset.unwrap_or(0);
        let result = unsafe {
            libc::sendfile(
                out_fd,
                in_fd,
                if offset.is_some() { &mut off } else { std::ptr::null_mut() },
                count,
            )
        };

        if result < 0 {
            return Err(Error::last_os_error());
        }

        Ok(result)
    }
}

pub struct RingBuffer {
    buffer: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
    capacity: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0u8; capacity],
            read_pos: 0,
            write_pos: 0,
            capacity,
        }
    }

    pub fn available_read(&self) -> usize {
        if self.write_pos >= self.read_pos {
            self.write_pos - self.read_pos
        } else {
            self.capacity - self.read_pos + self.write_pos
        }
    }

    pub fn available_write(&self) -> usize {
        self.capacity - self.available_read() - 1
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        let available = self.available_write();
        let to_write = data.len().min(available);

        for i in 0..to_write {
            self.buffer[self.write_pos] = data[i];
            self.write_pos = (self.write_pos + 1) % self.capacity;
        }

        to_write
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let available = self.available_read();
        let to_read = buf.len().min(available);

        for i in 0..to_read {
            buf[i] = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.capacity;
        }

        to_read
    }

    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let available = self.available_read();
        let to_peek = buf.len().min(available);
        let mut pos = self.read_pos;

        for i in 0..to_peek {
            buf[i] = self.buffer[pos];
            pos = (pos + 1) % self.capacity;
        }

        to_peek
    }

    pub fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.available_read() == 0
    }

    pub fn is_full(&self) -> bool {
        self.available_write() == 0
    }
}

pub struct MmapBuffer {
    ptr: *mut c_void,
    size: usize,
}

impl MmapBuffer {
    pub fn new(size: usize) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }

        Ok(Self { ptr, size })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.size) }
    }

    pub fn advise_sequential(&self) -> io::Result<()> {
        let result = unsafe {
            libc::madvise(self.ptr, self.size, libc::MADV_SEQUENTIAL)
        };

        if result != 0 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }

    pub fn advise_willneed(&self) -> io::Result<()> {
        let result = unsafe {
            libc::madvise(self.ptr, self.size, libc::MADV_WILLNEED)
        };

        if result != 0 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }
}

impl Drop for MmapBuffer {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.size);
        }
    }
}

unsafe impl Send for MmapBuffer {}
unsafe impl Sync for MmapBuffer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer() {
        let mut rb = RingBuffer::new(10);
        
        let written = rb.write(b"hello");
        assert_eq!(written, 5);
        assert_eq!(rb.available_read(), 5);
        
        let mut buf = [0u8; 5];
        let read = rb.read(&mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf, b"hello");
        assert!(rb.is_empty());
    }

    #[test]
    fn test_ring_buffer_wrap() {
        let mut rb = RingBuffer::new(5);
        
        rb.write(b"abc");
        let mut buf = [0u8; 2];
        rb.read(&mut buf);
        
        rb.write(b"def");
        assert_eq!(rb.available_read(), 4);
    }

    #[test]
    fn test_mmap_buffer() {
        let mut mmap = MmapBuffer::new(4096).unwrap();
        
        let slice = mmap.as_mut_slice();
        slice[0] = 42;
        slice[100] = 99;
        
        assert_eq!(mmap.as_slice()[0], 42);
        assert_eq!(mmap.as_slice()[100], 99);
    }
}