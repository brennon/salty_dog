require 'openssl'

module SaltyDog
  class PBKDF2
    ALLOWED_DIGESTS = [:sha1, :sha224, :sha256, :sha384, :sha512]
    
    def self.digest(options = {})
      digest = options[:digest] || :sha512
      self.build_digest(digest)
      
      check_key_length_requirements(options[:length])
      @length = options[:length]

      @l = (@length / @digest.length).ceil
      @r = @length - (@l - 1) * @digest.length

      self.calculate_key(@digest, options[:password], options[:salt], @l, @r, options[:iterations]).unpack('H*')[0]
    end

    # Build the appropriate digest
    def self.build_digest(digest)
      if !ALLOWED_DIGESTS.include?(digest)
        raise PBKDF2Error, 'Invalid digest'
      end

      klass = "OpenSSL::Digest::#{digest.to_s.upcase}"
      @digest = Object::const_get(klass).new
    end


    # Check desired key length requirements. These are:
    #
    # - Must be present
    # - Must be strictly positive
    # - Must be no larger than (2^32 - 1) * digest length of the chosen hash
    # function
    #
    # Raises a PBKDF2Error if any of these requirements are not met.
    def self.check_key_length_requirements(length)
      raise PBKDF2Error, 'A key length must be provided' if !length
      raise PBKDF2Error, 'Desired key is too long' if ((2**32 - 1) * @digest.length) < length
      raise PBKDF2Error, 'Desired key length must be positive' if length < 0
    end

    # XOR two strings +a+ and +b+.
    #
    # Raises a PBKDF2Error if +a+ and +b+ are not the same length.
    #
    # Returns a string of bytes representing the XORed value.
    def self.xor(x, y)
      raise PBKDF2Error, 'XOR arguments are not the same length' if x.length - y.length != 0 
      output = "".encode('ASCII-8BIT')

      x.bytes.zip(y.bytes) { |x,y| output << (x^y) }
      output
    end

    def self.prf(digest, password, seed)
      raise PBKDF2Error if !password || !seed
      OpenSSL::HMAC.digest(digest, password, seed)
    end

    def self.xor_sum(digest, password, salt, iterations, block_number)
      packed_index = [block_number].pack("N")
      seed = salt + packed_index
      final = self.prf(digest, password, seed)
      u = final

      for i in 2..iterations do
        u = self.prf(digest, password, u)
        final = self.xor(final, u)
      end

      final
    end

    def self.calculate_key(digest, password, salt, l, r, iterations)
      t = ""

      for i in 1..l+1 do
        t << self.xor_sum(digest, password, salt, iterations, i)
      end

      total_length = digest.length * (l-1) + r
      sliced = t.slice(0..total_length - 1)
      sliced
    end
  end

  class PBKDF2Error < StandardError
  end
end

