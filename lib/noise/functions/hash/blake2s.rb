# frozen_string_literal: true

module Noise
  module Functions
    module Hash
      class Blake2s
        HASHLEN = 32
        BLOCKLEN = 64
        def hash(data)
          Noise::Functions::Hash::Blake2sDigester.new.update(data).digest
        end

        def hashlen
          HASHLEN
        end

        def blocklen
          BLOCKLEN
        end
      end

      class Blake2sHMAC < HMAC::Base
        def initialize(key = '')
          super(Blake2sDigester, Blake2s::BLOCKLEN, Blake2s::HASHLEN, key)
        end
        public_class_method :new, :digest, :hexdigest
      end

      class Blake2sDigester
        IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
        SIGMA = [
          [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ],
          [ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 ],
          [ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 ],
          [ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 ],
          [ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 ],
          [ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 ],
          [ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 ],
          [ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 ],
          [ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 ],
          [ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 ]
        ]

        def initialize(key: '')
          @key = key
          @ctx = init(Blake2s::HASHLEN, @key.unpack("C*"))
        end

        def update(data)
          update_internal(@ctx, data.unpack("C*"))
          self
        end

        def digest
          out = []
          final(@ctx, out)
          out.pack("C*")
        end


          # @return context
          def init(out_len, key)
            raise ArgumentError if out_len == 0 || out_len > 32
            h = IV.dup
            h[0] ^= 0x01010000 ^ (key.size << 8) ^ out_len
            t = [0, 0]
            c = 0
            b = Array.new(Blake2s::BLOCKLEN).fill(0, key.size)
            ctx = Context.new(b, h, t, c, out_len)
            if key.size > 0
              update_internal(ctx, key)
              ctx.c = 64
            end
            ctx
          end

          def update_internal(ctx, input)
            input.size.times do |i|
              if ctx.c == Blake2s::BLOCKLEN
                ctx.t[0] += ctx.c
                # if ctx.t[0] < ctx.c
                if ctx.t[0] > 0xFFFFFFFF
                  ctx.t[0] = ctx.t[0] - 0xFFFFFFFF
                  ctx.t[1] += 1
                end
                compress(ctx, false)
                ctx.c = 0
              end

              ctx.b[ctx.c] = input[i]
              ctx.c += 1
            end
          end

          def final(ctx, out)
            ctx.t[0] += ctx.c
            if ctx.t[0] > 0xFFFFFFFF
              ctx.t[0] = ctx.t[0] - 0xFFFFFFFF
              ctx.t[1] += 1
            end

            while ctx.c < Blake2s::BLOCKLEN
              ctx.b[ctx.c] = 0
              ctx.c += 1
            end
            compress(ctx, true)
            ctx.out_len.times do |i|
              out << ((ctx.h[i >> 2] >> (8 * (i & 3))) & 0xff)
            end
          end

        private

        def to_int32(x)
          x = x & 0xFFFFFFFF
          x < 0x80000000 ? x : x - 2**32
        end

        def rshift(x, y, range=32)
          (x + (x > 0 ? 0 : 2 ** range)) >> y
        end

        def rotr32(x, y)
          to_int32(x << (32 - y) ^ rshift(x & 0xFFFFFFFF, y))
        end

        def get32(p0, p1, p2, p3)
          (p0 & 0xFF) | ((p1 & 0xFF) << 8) | ((p2 & 0xFF) << 16) | ((p3 & 0xFF) << 24)
        end

        def mix_g(v, a, b, c, d, x, y)
          v[a] = v[a] + v[b] + x
          v[d] = v[d] ^ v[a]
          v[d] = rotr32(v[d], 16)
          v[c] = v[c] + v[d]
          v[b] = v[b] ^ v[c]
          v[b] = rotr32(v[b], 12)

          v[a] = v[a] + v[b] + y
          v[d] = v[d] ^ v[a]
          v[d] = rotr32(v[d], 8)
          v[c] = v[c] + v[d]
          v[b] = v[b] ^ v[c]
          v[b] = rotr32(v[b], 7)
        end

        def compress(ctx, last)
          v = Array.new(16)
          m = Array.new(16)
          8.times do |i|
            v[i] = ctx.h[i]
            v[i + 8] = IV[i]
          end

          v[12] ^= ctx.t[0]
          v[13] ^= ctx.t[1]

          if last
            v[14] = ~v[14] & 0xFFFFFFFF
          end

          16.times do |i|
            m[i] = get32(ctx.b[4 * i], ctx.b[4 * i + 1], ctx.b[4 * i + 2], ctx.b[4 * i + 3])
          end

          10.times do |i|
            mix_g(v, 0, 4,  8, 12, m[SIGMA[i][ 0]], m[SIGMA[i][ 1]])
            mix_g(v, 1, 5,  9, 13, m[SIGMA[i][ 2]], m[SIGMA[i][ 3]])
            mix_g(v, 2, 6, 10, 14, m[SIGMA[i][ 4]], m[SIGMA[i][ 5]])
            mix_g(v, 3, 7, 11, 15, m[SIGMA[i][ 6]], m[SIGMA[i][ 7]])
            mix_g(v, 0, 5, 10, 15, m[SIGMA[i][ 8]], m[SIGMA[i][ 9]])
            mix_g(v, 1, 6, 11, 12, m[SIGMA[i][10]], m[SIGMA[i][11]])
            mix_g(v, 2, 7,  8, 13, m[SIGMA[i][12]], m[SIGMA[i][13]])
            mix_g(v, 3, 4,  9, 14, m[SIGMA[i][14]], m[SIGMA[i][15]])
          end

          8.times do |i|
            ctx.h[i] ^= v[i] ^ v[i + 8]
          end
        end

        class Context
          attr_accessor :b, :h, :t, :c, :out_len
          def initialize(b, h, t, c, out_len)
            @b = b
            @h = h
            @t = t
            @c = c
            @out_len = out_len
          end
        end
      end
    end
  end
end
