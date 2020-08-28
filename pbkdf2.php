<?php
 // 3rd party PBKDF Hashing library --

if (!function_exists('hash_pbkdf2'))
{
    function hash_pbkdf2($algo, $password, $salt, $count, $length = 0, $raw_output = false)
    {
        if (!in_array(strtolower($algo), hash_algos())) trigger_error(__FUNCTION__ . '(): Unknown hashing algorithm: ' . $algo, E_USER_WARNING);
        if (!is_numeric($count)) trigger_error(__FUNCTION__ . '(): expects parameter 4 to be long, ' . gettype($count) . ' given', E_USER_WARNING);
        if (!is_numeric($length)) trigger_error(__FUNCTION__ . '(): expects parameter 5 to be long, ' . gettype($length) . ' given', E_USER_WARNING);
        if ($count <= 0) trigger_error(__FUNCTION__ . '(): Iterations must be a positive integer: ' . $count, E_USER_WARNING);
        if ($length < 0) trigger_error(__FUNCTION__ . '(): Length must be greater than or equal to 0: ' . $length, E_USER_WARNING);

        $output = '';
        $block_count = $length ? ceil($length / strlen(hash($algo, '', $raw_output))) : 1;
        for ($i = 1; $i <= $block_count; $i++)
        {
            $last = $xorsum = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            for ($j = 1; $j < $count; $j++)
            {
                $xorsum ^= ($last = hash_hmac($algo, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if (!$raw_output) $output = bin2hex($output);
        return $length ? substr($output, 0, $length) : $output;
    }
}
?>

<?php
    /**
     * Password hashing with PBKDF2.
     * (modified to use the native php function if available)
     * Based on the pure PHP implementation of PBKDF2 which can be found on:
     * https://defuse.ca/php-pbkdf2.htm
     *
     * @author havoc AT defuse.ca (www: https://defuse.ca/php-pbkdf2.htm)
     * @author TheBlintOne
     *
     * @license Public Domain (so feel free to use it): http://en.wikipedia.org/wiki/Public_domain
     */
 
    /**
     * Class to encapsulate the PBKDF2 functions
     *
     * @author havoc AT defuse.ca (www: https://defuse.ca/php-pbkdf2.htm)
     * @author TheBlintOne
     */
    class PBKDF2
    {
        // These constants may be changed without breaking existing hashes.
        const PBKDF2_HASH_ALGORITHM = "sha256";
        const PBKDF2_ITERATIONS = 1000;
        const PBKDF2_SALT_BYTES = 24;
        const PBKDF2_HASH_BYTES = 24;
 
        const HASH_SECTIONS = 4;
        const HASH_ALGORITHM_INDEX = 0;
        const HASH_ITERATION_INDEX = 1;
        const HASH_SALT_INDEX = 2;
        const HASH_PBKDF2_INDEX = 3;
 
        /**
         * Creates a hash for the given password
         *
         * @param string $password    the password to hash
         * @return string             the hashed password in format "algorithm:iterations:salt:hash"
         */
        public function create_hash( $password )
        {
            $salt = base64_encode( mcrypt_create_iv( PBKDF2::PBKDF2_SALT_BYTES, MCRYPT_DEV_URANDOM ) );
            return PBKDF2::PBKDF2_HASH_ALGORITHM . ":" . PBKDF2::PBKDF2_ITERATIONS . ":" .  $salt . ":" .
                base64_encode( $this->hash(
                    PBKDF2::PBKDF2_HASH_ALGORITHM,
                    $password,
                    $salt,
                    PBKDF2::PBKDF2_ITERATIONS,
                    PBKDF2::PBKDF2_HASH_BYTES,
                    true
                ) );
        }
 
        /**
         * Checks if the given password matches the given hash created by PBKDF::create_hash( string )
         *
         * @param string $password     the password to check
         * @param string $good_hash    the hash which should be match the password
         * @return boolean             true if $password and $good_hash match, false otherwise
         *
         * @see PBKDF2::create_hash
         */
        public function validate_password( $password, $good_hash )
        {
            $params = explode( ":", $good_hash );
            if( count( $params ) < HASH_SECTIONS )
               return false;
            $pbkdf2 = base64_decode( $params[ PBKDF2::HASH_PBKDF2_INDEX ] );
            return slow_equals(
                $pbkdf2,
                $this->hash(
                    $params[ PBKDF2::HASH_ALGORITHM_INDEX ],
                    $password,
                    $params[ PBKDF2::HASH_SALT_INDEX ],
                    (int)$params[ PBKDF2::HASH_ITERATION_INDEX ],
                    strlen( $pbkdf2 ),
                    true
                )
            );
        }
 
        /**
         * Compares two strings $a and $b in length-constant time
         *
         * @param string $a    the first string
         * @param string $b    the second string
         * @return boolean     true if they are equal, false otherwise
         */
        public function slow_equals( $a, $b )
        {
            $diff = strlen( $a ) ^ strlen( $b );
            for( $i = 0; $i < strlen( $a ) && $i < strlen( $b ); $i++ )
            {
                $diff |= ord( $a[ $i ] ) ^ ord( $b[ $i ] );
            }
            return $diff === 0;
        }
 
        /**
         * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
         *
         * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
         *
         * This implementation of PBKDF2 was originally created by https://defuse.ca
         * With improvements by http://www.variations-of-shadow.com
         * Added support for the native PHP implementation by TheBlintOne
         *
         * @param string $algorithm                                 the hash algorithm to use. Recommended: SHA256
         * @param string $password                                  the Password
         * @param string $salt                                      a salt that is unique to the password
         * @param int $count                                        iteration count. Higher is better, but slower. Recommended: At least 1000
         * @param int $key_length                                   the length of the derived key in bytes
         * @param boolean $raw_output [optional] (default false)    if true, the key is returned in raw binary format. Hex encoded otherwise
         * @return string                                           a $key_length-byte key derived from the password and salt,
         *                                                          depending on $raw_output this is either Hex encoded or raw binary
         * @throws Exception                                        if the hash algorithm are not found or if there are invalid parameters
         */
        public function hash( $algorithm, $password, $salt, $count, $key_length, $raw_output = false )
        {
            $algorithm = strtolower( $algorithm );
            if( !in_array( $algorithm, hash_algos() , true ) )
                throw new Exception( 'PBKDF2 ERROR: Invalid hash algorithm.' );
            if( $count <= 0 || $key_length <= 0 )
                throw new Exception( 'PBKDF2 ERROR: Invalid parameters.' );
 
            // use the native implementation of the algorithm if available
            if( function_exists( "hash_pbkdf2" ) )
            {
                return hash_pbkdf2( $algorithm, $password, $salt, $count, $key_length, $raw_output );
            }
 
            $hash_length = strlen( hash( $algorithm, "", true ) );
            $block_count = ceil( $key_length / $hash_length );
 
            $output = "";
            for( $i = 1; $i <= $block_count; $i++ )
            {
                // $i encoded as 4 bytes, big endian.
                $last = $salt . pack( "N", $i );
                // first iteration
                $last = $xorsum = hash_hmac( $algorithm, $last, $password, true );
                // perform the other $count - 1 iterations
                for( $j = 1; $j < $count; $j++ )
                {
                    $xorsum ^= ( $last = hash_hmac( $algorithm, $last, $password, true ) );
                }
                $output .= $xorsum;
            }
 
            if( $raw_output )
                return substr( $output, 0, $key_length );
            else
                return bin2hex( substr( $output, 0, $key_length ) );
        }
    }

class Bcrypt
{
  private $rounds;

  public function __construct($rounds = 12)
  {
    if (CRYPT_BLOWFISH != 1) {
      throw new Exception("bcrypt not supported in this installation. See http://php.net/crypt");
    }

    $this->rounds = $rounds;
  }

  public function hash($input)
  {
    $hash = crypt($input, $this->getSalt());

    if (strlen($hash) > 13)
      return $hash;

    return false;
  }

  public function verify($input, $existingHash)
  {
    $hash = crypt($input, $existingHash);

    return $hash === $existingHash;
  }

  private function getSalt()
  {
    $salt = sprintf('$2a$%02d$', $this->rounds);

    $bytes = $this->getRandomBytes(16);

    $salt .= $this->encodeBytes($bytes);

    return $salt;
  }

  private $randomState;
  private function getRandomBytes($count)
  {
    $bytes = '';

    if (function_exists('openssl_random_pseudo_bytes') &&
        (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN')) { // OpenSSL is slow on Windows
      $bytes = openssl_random_pseudo_bytes($count);
    }

    if ($bytes === '' && is_readable('/dev/urandom') &&
       ($hRand = @fopen('/dev/urandom', 'rb')) !== FALSE) {
      $bytes = fread($hRand, $count);
      fclose($hRand);
    }

    if (strlen($bytes) < $count) {
      $bytes = '';

      if ($this->randomState === null) {
        $this->randomState = microtime();
        if (function_exists('getmypid')) {
          $this->randomState .= getmypid();
        }
      }

      for ($i = 0; $i < $count; $i += 16) {
        $this->randomState = md5(microtime() . $this->randomState);

        if (PHP_VERSION >= '5') {
          $bytes .= md5($this->randomState, true);
        } else {
          $bytes .= pack('H*', md5($this->randomState));
        }
      }

      $bytes = substr($bytes, 0, $count);
    }

    return $bytes;
  }

  private function encodeBytes($input)
  {
    // The following is code from the PHP Password Hashing Framework
    $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    $output = '';
    $i = 0;
    do {
      $c1 = ord($input[$i++]);
      $output .= $itoa64[$c1 >> 2];
      $c1 = ($c1 & 0x03) << 4;
      if ($i >= 16) {
        $output .= $itoa64[$c1];
        break;
      }

      $c2 = ord($input[$i++]);
      $c1 |= $c2 >> 4;
      $output .= $itoa64[$c1];
      $c1 = ($c2 & 0x0f) << 2;

      $c2 = ord($input[$i++]);
      $c1 |= $c2 >> 6;
      $output .= $itoa64[$c1];
      $output .= $itoa64[$c2 & 0x3f];
    } while (true);

    return $output;
  }
} ?>
