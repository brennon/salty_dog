require 'openssl'

module SaltyDog

  ##
  # PBKDF2 encapsulates the identically-named password-based key derivation
  # function outlined in PKCS[http://www.rsa.com/rsalabs/node.asp?id=2127] #5: Password-Based Cryptography Standard. PBKDF1, as set 
  # forth in the same document, has been recommended for removal from use, and
  # thus is not implemented in SaltyDog. If you just need to generate keys,
  # skip down to ::digest:

  class PBKDF2

    ##
    # According to the recommendation, the hash functions that are supported
    # for HMAC (pseudorandom number generation) are SHA1, SHA224, SHA256,
    # SHA384, AND SHA512. These are provided here.

    ALLOWED_DIGESTS = [:sha1, :sha224, :sha256, :sha384, :sha512]
    
    ##
    # The primary point of entry for SaltyDog::PBKDF2. The available options
    # are:
    #
    # - :digest - One of +:sha1+, +:sha224+, +:sha256+, +:sha384+, or
    # +:sha512+. Defaults to +:sha512+.
    # - :password - A password for use in deriving the key. Required, and must be a string.
    # - :salt - A salt that is concatenated to the password in key derivation.
    # Required, and must ba a string.
    # - :length - The desired length, in bytes, of the derived key. Required.
    # - :iterations - The number of iterations to be used in key derivation.
    # Defaults to 10000.
    #
    # Returns a hex-string representing the derived key.

    def self.digest(options = {})
      digest = options[:digest] || :sha512
      self.build_digest(digest)
      
      check_key_length_requirements(options[:length])
      @length = options[:length]
      @iterations = options[:iterations] || 10000

      @l = (@length / @digest.length).ceil
      @r = @length - (@l - 1) * @digest.length

      self.calculate_key(@digest, options[:password].to_s, options[:salt].to_s, @l, @r, @iterations).unpack('H*')[0]
    end

    ##
    # Build the derived key. Called directly by SaltyDog::PBKDF2.digest.

    def self.build_digest(digest)
      if !ALLOWED_DIGESTS.include?(digest)
        raise PBKDF2Error, 'Invalid digest'
      end

      klass = "OpenSSL::Digest::#{digest.to_s.upcase}"
      @digest = Object::const_get(klass).new
    end

    ##
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

    ##
    # XOR two strings +x+ and +y+.
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

    ##
    # Uses a pseudorandom function based on the digest function provided to
    # SaltyDog::PBKDF2.digest to generate input for each iteration round.

    def self.prf(digest, password, seed)
      raise PBKDF2Error if !password || !seed
      OpenSSL::HMAC.digest(digest, password, seed)
    end

    ##
    # Within each iteration, SaltyDog::PBKDF2.xor_sum XORs each block of output
    # from SaltyDog::PBKDF2.prf. The result of this chain of XORs is provided
    # to ::calculate_key to be used as a block of the final derived key.

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

    ##
    # The workhorse of SaltyDog::PBKDF2. ::calculate_key initiates the
    # specified number of iterations of hashing in calculating each block of
    # the derived key. All blocks are then concatenated together in computing
    # the final derived key.

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

