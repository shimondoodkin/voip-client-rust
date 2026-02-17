/// Resampling utilities for VoIP audio.
///
/// Provides linear resampler and ring buffer for converting between
/// device sample rates and the internal 16kHz rate.

/// 16kHz internal sample rate (wideband telephony).
pub const INTERNAL_RATE: u32 = 16000;
/// 320 samples = 20ms at 16kHz.
pub const FRAME_SAMPLES: usize = 320;

/// Simple linear interpolation resampler.
pub struct LinearResampler {
    in_rate: u32,
    out_rate: u32,
    phase: f32,
    last: f32,
}

impl LinearResampler {
    pub fn new(in_rate: u32, out_rate: u32) -> Self {
        Self {
            in_rate,
            out_rate,
            phase: 0.0,
            last: 0.0,
        }
    }

    pub fn process(&mut self, input: &[f32], output: &mut Vec<f32>) {
        output.clear();
        if self.in_rate == self.out_rate {
            output.extend_from_slice(input);
            if let Some(&v) = input.last() {
                self.last = v;
            }
            return;
        }

        let ratio = self.in_rate as f32 / self.out_rate as f32;
        let mut pos = self.phase;

        while pos < input.len() as f32 {
            let idx = pos.floor() as usize;
            let frac = pos - idx as f32;
            let s0 = if idx == 0 { self.last } else { input[idx - 1] };
            let s1 = input[idx.min(input.len() - 1)];
            output.push(s0 + (s1 - s0) * frac);
            pos += ratio;
        }

        self.phase = pos - input.len() as f32;
        if let Some(&v) = input.last() {
            self.last = v;
        }
    }
}

/// Ring buffer for accumulating resampled audio into fixed-size frames.
pub struct ResampleBuffer {
    buf: Vec<f32>,
    head: usize,
    tail: usize,
    count: usize,
}

impl ResampleBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0.0; capacity],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn push(&mut self, samples: &[f32]) {
        for &s in samples {
            if self.count == self.buf.len() {
                self.tail = (self.tail + 1) % self.buf.len();
                self.count -= 1;
            }
            self.buf[self.head] = s;
            self.head = (self.head + 1) % self.buf.len();
            self.count += 1;
        }
    }

    pub fn pop_exact(&mut self, out: &mut [f32]) -> bool {
        if self.count < out.len() {
            return false;
        }
        for v in out.iter_mut() {
            *v = self.buf[self.tail];
            self.tail = (self.tail + 1) % self.buf.len();
        }
        self.count -= out.len();
        true
    }
}
