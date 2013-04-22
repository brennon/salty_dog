require 'test_helper'
require 'test/unit'
require 'salty_dog'

class PBKDF2Tests < Test::Unit::TestCase
  include SaltyDog

  def params
    {
      digest: :sha1,
      salt: 'NaCl',
      password: 'password',
      length: 128,
      iterations: 3
    }
  end

  def digest_sha1
    OpenSSL::Digest.new('sha1')
  end

  def digest_sha512
    OpenSSL::Digest.new('sha512')
  end

  def hexify(str)
    str.unpack('H*')[0]
  end

  def assert_pbkdf_error(&block)
    assert_raise PBKDF2Error do
      block.call
    end
  end

  def test_pbkdf2_does_not_accept_sha
    assert_pbkdf_error { PBKDF2.digest(digest: :sha) }
  end

  def test_digest_does_not_accept_other_digests
    assert_pbkdf_error { PBKDF2.digest(digest: :my_algorithm) }
  end

  def test_works_without_a_digest
  end

  def test_digest_rejects_a_key_length_that_is_too_long
    assert_pbkdf_error { PBKDF2.digest(length: 274877906881) }
  end

  def test_digest_requires_a_key_length
    assert_pbkdf_error { PBKDF2.digest }
  end

  def test_digest_requires_a_positive_key_length
    assert_pbkdf_error { PBKDF2.digest(length: -1) }
  end

  def test_xor_requires_string_of_equal_lengths
    assert_pbkdf_error { PBKDF2.xor("abc", "abcd") }
  end

  def test_xor_result
    a = "abc"
    b = "def"
    expected = "".encode("ASCII-8BIT")
    [5,7,5].each { |i| expected += i.chr }
    assert_equal expected, PBKDF2.xor(a, b)
  end

  def test_pseudorandom_function
    seed = params[:salt] + [14].pack('N')
    expected = "31fd601b914005a4127559d2f04a2f73908201f0ce1e3614acc82d4e3b0b028eade985265421bf4ac95d2bee952d9bc7b215530d598a4d11ccbcfb773a523f86"
    actual = hexify(PBKDF2.prf(digest_sha512, params[:password], seed))
    assert_equal expected, actual
  end

  def test_prf_fails_without_a_password
    seed = params[:salt] + [14].pack('N')
    assert_pbkdf_error { PBKDF2.prf(digest_sha512, nil, seed) }
  end

  def test_prf_fails_without_a_seed
    assert_pbkdf_error { PBKDF2.prf(digest_sha512, params[:password], nil) }
  end

  def test_xor_sum
    actual = hexify(PBKDF2.xor_sum(
      digest_sha1, 
      params[:password], 
      params[:salt], 
      2, 
      1)
    )
    assert_equal '2e3f712a53087c78ba377cbc871b003f978f58f8', actual
  end

  def test_calculate_key
    l = (params[:length] / digest_sha1.length).ceil
    r = params[:length] - ((l - 1) * digest_sha1.length)
    iterations = 3
    actual = hexify(PBKDF2.calculate_key(
      digest_sha1, 
      params[:password], 
      params[:salt], 
      l, 
      r, 
      params[:iterations])
    )
    expected = "d4c1f846f67205a1cc1c27f9581c26d9651a9aba91ab3fd05e945102fe73397a4131b3c1604f1cbdf8c2a901101af97116d94ab7591a1f7d372e421d98aa19ba75e34f607322f2c127fd0ebdbc946da8f481c35fa9f6512be5f587fcd386c0773a4646df3096d677585b6c39edab7ba6c5ecd1e86837cabf040191bc146a5394"
    assert_equal expected, actual
  end

  def test_full_stack
    actual = PBKDF2.digest(params)
    expected = "d4c1f846f67205a1cc1c27f9581c26d9651a9aba91ab3fd05e945102fe73397a4131b3c1604f1cbdf8c2a901101af97116d94ab7591a1f7d372e421d98aa19ba75e34f607322f2c127fd0ebdbc946da8f481c35fa9f6512be5f587fcd386c0773a4646df3096d677585b6c39edab7ba6c5ecd1e86837cabf040191bc146a5394"
    assert_equal expected, actual
  end
end
