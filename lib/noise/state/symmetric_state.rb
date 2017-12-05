# frozen_string_literal: true

module Noise
  module State
    # A SymmetricState object contains a CipherState plus the following variables:
    #
    # - ck: A chaining key of HASHLEN bytes.
    # - h: A hash output of HASHLEN bytes.
    #
    class SymmetricState
      attr_reader :h, :ck
      attr_reader :cipher_state

      def initialize_symmetric(protocol)
        # puts "SymmetricState#initialize_symmetric:#{protocol.name}"
        @protocol = protocol
        @ck = @h =
                if @protocol.name.length <= @protocol.hash_fn.hashlen
                  @protocol.name.ljust(@protocol.hash_fn.hashlen, "\x00")
                else
                  @protocol.hash_fn.hash(@protocol.name)
                end

        @cipher_state = CipherState.new(cipher: @protocol.cipher_fn)
        @cipher_state.initialize_key(nil)
        @protocol.cipher_state_handshake = @cipher_state
      end

      def mix_key(input_key_meterial)
        puts "    SymmetricState#mix_key(start)---------------------------"
        puts "        ck=#{@ck.bth}"
        puts "        input_key_meterial=#{input_key_meterial.bth}"
        @ck, temp_k = @protocol.hkdf_fn.call(@ck, input_key_meterial, 2)
        temp_k = truncate(temp_k)
        @cipher_state.initialize_key(temp_k)
        puts "    SymmetricState#mix_key(end)-----------------------------------"
      end

      # data [String] binary string
      def mix_hash(data)
        puts "        SymmetricState#mix_hash(start)---------------------------"
        puts "            h=#{@h.bth}"
        puts "            data=#{data.bth}"
        @h = @protocol.hash_fn.hash(@h + data)
        puts "            h=#{@h.bth}"
        puts "        SymmetricState#mix_hash(end)---------------------------"
      end

      def mix_key_and_hash(input_key_meterial)
        puts "    SymmetricState#mix_key_and_hash(start)---------------------------"
        puts "        input_key_meterial=#{input_key_meterial.bth}"
        puts "        @ck=#{@ck.bth}"
        @ck, temp_h, temp_k = @protocol.hkdf_fn.call(@ck, input_key_meterial, 3)
        puts "        @ck=#{@ck.bth}"
        puts "        temp_h=#{temp_h.bth}"
        puts "        temp_k=#{temp_k.bth}"
        mix_hash(temp_h)
        temp_k = truncate(temp_k)
        @cipher_state.initialize_key(temp_k)
        puts "SymmetricState#mix_key_and_hash(end)---------------------------"
      end

      def handshake_hash
        @h
      end

      def encrypt_and_hash(plaintext)
        puts "    SymmetricState#encrypt_and_hash---------------------------"
        puts "        plaintext=#{plaintext.bth}"
        puts "        @h=#{@h.bth}"
        ciphertext = @cipher_state.encrypt_with_ad(@h, plaintext)
        puts "        ciphertext=#{ciphertext.bth}"
        mix_hash(ciphertext)
        puts "        ciphertext=#{ciphertext.bth}"
        ciphertext
      end

      def decrypt_and_hash(ciphertext)
        puts "    SymmetricState#decrypt_and_hash(start)---------------------------"
        plaintext = @cipher_state.decrypt_with_ad(@h, ciphertext)
        puts "        ciphertext=#{ciphertext}"
        mix_hash(ciphertext)
        puts "        ciphertext=#{ciphertext}"
        puts "    SymmetricState#decrypt_and_hash(end)---------------------------"
        plaintext
      end

      def split
        temp_k1, temp_k2 = @protocol.hkdf_fn.call(@ck, '', 2)
        temp_k1 = truncate(temp_k1)
        temp_k2 = truncate(temp_k2)
        c1 = CipherState.new(cipher: @protocol.cipher_fn)
        c2 = CipherState.new(cipher: @protocol.cipher_fn)
        c1.initialize_key(temp_k1)
        c2.initialize_key(temp_k2)
        if @protocol.initiator
          @protocol.cipher_state_encrypt = c1
          @protocol.cipher_state_decrypt = c2
        else
          @protocol.cipher_state_encrypt = c2
          @protocol.cipher_state_decrypt = c1
        end
        @protocol.handshake_done
        [c1, c2]
      end

      def truncate(temp_k)
        @protocol.hash_fn.hashlen == 64 ? temp_k[0, 32] : temp_k
      end
    end
  end
end
