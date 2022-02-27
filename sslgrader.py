import hashlib, ssl, socket, requests
import OpenSSL
from datetime import datetime
import optparse as op

parser = op.OptionParser()

parser.add_option("-i", dest = "inputfile", help = "input filename")
parser.add_option("-o", dest = "outputfile", help = "output filename. Output only works in quick mode")
parser.add_option("-m", dest = "mode", help = "modes: quick, summ, full")
parser.add_option("-u", dest = "url", help = "single URL")

(options, args) = parser.parse_args()

input_file = options.inputfile
output_file = options.outputfile
mode = options.mode
hostname = options.url

# Mozilla CA store
mozilla_trusted_ca = 'https://curl.haxx.se/ca/cacert.pem'

def get_thumbprint():
  return hashlib.sha1(der).hexdigest()

def get_days_to_expiry():
  days_to_expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
  days_to_expiry = (days_to_expiry - datetime.now()).days
  return days_to_expiry, days_to_expiry > 0;

def get_key_length():
  public_key = openssl_cert.get_pubkey()
  key_length = public_key.bits()
  if key_length == 256:
    return 3072
  if key_length == 384:
    return 7680
  return key_length

def get_sig_algo():
  sig_algo = openssl_cert.get_signature_algorithm().decode()
  if 'sha256' in sig_algo.lower() or 'sha384' in sig_algo.lower():
    sig_hash_grade = 'Good'
  elif 'sha1' in sig_algo.lower():
    sig_hash_grade = 'Average'
  elif 'md5' in sig_algo.lower():
    sig_hash_grade = 'Bad'
  return (sig_algo, sig_hash_grade)

def get_key_ex():
  if cipher[0].startswith('TLS'):
    return 'NIL'
  elif not cipher[0].startswith('AES'):
    key_split = cipher[0].split('-')
    return key_split[0]
  return 'RSA'

def get_enc_mode():
  if 'GCM' in cipher[0]:
    return 'GCM'
  elif 'CHACHA20' in cipher[0]:
    return 'CHACHA20/POLY1305'
  else:
    return 'CBC'

def trust_check():
  ca_issuer = cert['caIssuers'][0]

  ca_issuer_crt = requests.get(ca_issuer)
  ca_issuer_crt = ca_issuer_crt.content
  root_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, ca_issuer_crt)
  root_cert_dict = dict(root_cert.get_issuer().get_components())
  root_cert_issuer = root_cert_dict[b'CN'].decode()

  trust_store = requests.get(mozilla_trusted_ca, 'rb')
  return root_cert_issuer, root_cert_issuer in trust_store.content.decode()

def verify_crl():
  try:
    crl_resp = requests.get(cert['crlDistributionPoints'][0])
    crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl_resp.content)

    crl_crypto = crl.to_cryptography()

    ca_resp = requests.get(cert['caIssuers'][0])
    ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, ca_resp.content)    

    ca_pub_key = ca.get_pubkey().to_cryptography_key()

    valid_crl = crl_crypto.is_signature_valid(ca_pub_key)
    return valid_crl
  except:
    return 0

def connect():
  global cert, cipher, openssl_cert

  ctx = ssl.create_default_context()
  with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
    s.connect((hostname, 443))
    cert = s.getpeercert()
    cert_version = s.version()
    cipher = s.cipher()
    der = s.getpeercert(True)
    pem = ssl.DER_cert_to_PEM_cert(der)
    openssl_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der)

  subject = dict(x[0] for x in cert['subject'])
  issued_to = subject['commonName']
  issuer = dict(x[0] for x in cert['issuer'])
  issued_by = issuer['commonName']

  #print('Domain:', hostname)

def part1_cert_verify():
  # Grading part 1: Certificate validity
  global trust_status, root_cert_issuer, trust_score, trust_percentage, cert_validity_status, expiry_date, days_to_expiry, cert_validity_score, cert_validity_percentage, crl_status_out, crl_status_score, crl_status_percentage, sig_algo, sig_hash_grade, sig_score, sig_percentage, total_cert_percentage

  # Declare dictionaries
  trust_response = {True:('Trusted',1), False:('Not trusted',0)}
  cert_expiry = {True:('Active', 1), False:('Expired', 0)}
  crl_status = {True:('Good', 1), False:('Bad', 0), 0:('No CRL',0)}
  sig_grade = {'Good':2, 'Average':1, 'Bad':0}

  # Trust Check for certificate to be signed by a well-known CA - checked against Mozilla's trusted CA store
  root_cert_issuer, trust_bool = trust_check()
  trust_status = trust_response[trust_bool][0]
  trust_score = trust_response[trust_bool][1]
  trust_percentage = trust_score/1*10

  # Expiry Check to ensure certificate is not invalid
  expiry_date = cert['notAfter']
  days_to_expiry, cert_validity = get_days_to_expiry()
  cert_validity_status = cert_expiry[cert_validity][0]
  cert_validity_score = cert_expiry[cert_validity][1]
  cert_validity_percentage = cert_expiry[cert_validity][1]/1*10

  # Invalid Check to ensure certificate is not revoked
  valid_crl = verify_crl()
  crl_status_out = crl_status[valid_crl][0]
  crl_status_score = crl_status[valid_crl][1]
  crl_status_percentage = crl_status_score/1*10

  # Secure Check to ensure certificate is not using an insecure signature like MD5 and below
  sig_algo, sig_hash_grade = get_sig_algo()
  sig_score = sig_grade[sig_hash_grade]
  sig_percentage = sig_score/2*10

  total_cert_percentage = trust_percentage + cert_validity_percentage + crl_status_percentage + sig_percentage

def part2_security_config():
  # Grading part 2: Security configuration checker
  global protocol_score, protocol_percentage, key_ex_value, key_ex_score, key_ex_percentage, key_len_score, key_len_percentage, total_key_percentage, enc_mode_value, enc_mode_score, enc_mode_percentage, key_str_value, key_str_score, key_str_percentage, total_cipher_percentage, total_security_percentage

  # Declare scores in dictionaries
  protocols = {'TLSv1.3':6,'TLSv1.2':5,'TLSv1.1':4, 'TLSv1.0':3, 'SSLv3':2, 'SSLv2':1}
  key_ex = {'NIL':6, 'ECDHE':6, 'DHE':5, 'ECDH':4, 'DH':3, 'RSA':2, 'SRP':1}
  key_len = {4096:5, 3072:4, 2048:3, 1024:2, 512:1, 7680:6} # 7680 gets extra points
  enc_mode = {'GCM':2, 'CHACHA20/POLY1305':1.5, 'CBC':1} # min 5% - divide by 2
  key_str = {256:2, 128:1}

  # Protocols scoring
  protocol_score = int(protocols[cipher[1]])
  protocol_percentage = protocol_score/6*20

  # Key exchange scoring
  key_ex_value = get_key_ex()
  key_ex_score = key_ex[key_ex_value]
  key_ex_percentage = key_ex_score/6*10
  key_len_score = key_len[get_key_length()]
  key_len_percentage = key_len_score/5*10
  total_key_percentage = key_ex_percentage + key_len_percentage

  # Cipher strength (Encryption)
  enc_mode_value = get_enc_mode()
  enc_mode_score = enc_mode[enc_mode_value]
  enc_mode_percentage = enc_mode_score/2*10
  key_str_value = cipher[2]
  key_str_score = key_str[key_str_value]
  key_str_percentage = key_str_score/2*10
  total_cipher_percentage = enc_mode_percentage + key_str_percentage

  total_security_percentage = protocol_percentage + total_key_percentage + total_cipher_percentage

def grade():
  total_score = total_cert_percentage + total_security_percentage

  if total_score >= 80:
    grade = 'A'
  elif total_score >= 70:
    grade = 'B'
  elif total_score >= 60:
    grade = 'C'
  elif total_score >= 50:
    grade = 'D'
  else:
    grade = 'F'
  
  return (total_score, grade)

def print_part1():
  # Printing for part 1
  print('Certificate validity checker (40%):')
  print('\nTrust Check:')
  print('Certificate signed off by a well-known CA: {}\nRoot certificate issuer: {}\nScore: {} ({:.2f}%)'.format(trust_status, root_cert_issuer, trust_score, trust_percentage))
  print('\nExpiry Check:')
  print('Certificate status: {}\nExpires on: {}\nDays to expiry: {}\nScore: {} ({:.2f}%)'.format(cert_validity_status, expiry_date, days_to_expiry, cert_validity_score, cert_validity_percentage))
  print('\nInvalid Check:')
  print('CRL status: {}\nScore: {} ({:.2f}%)'.format(crl_status_out, crl_status_score, crl_status_percentage))
  print('\nSecure Check:')
  print('Signature algorithm: {}\nGrade: {}\nScore: {} ({:.2f}%)'.format(sig_algo, sig_hash_grade, sig_score, sig_percentage))
  print('\nTotal score (part 1): {}%\n'.format(total_cert_percentage))

def print_part2():
  # Printing for part 2
  print('Security configuration checker (60%)')
  print('\nProtocol: {}\nScore: {} ({:.2f}%)'.format(cipher[1], protocol_score, protocol_percentage))
  print('\nKey exchange: {}\nScore: {} ({:.2f}%)'.format(key_ex_value, key_ex_score, key_ex_percentage))
  print('Key length: {} bits\nScore: {} ({:.2f}%)'.format(get_key_length(), key_len_score, key_len_percentage))
  print('Total key exchange score: {:.2f}%'.format(total_key_percentage))
  print('\nEncryption mode: {}\nScore: {} ({:.2f}%)'.format(enc_mode_value, enc_mode_score, enc_mode_percentage))
  print('Key strength: {}\nScore: {} ({:.2f}%)'.format(key_str_value, key_str_score, key_str_percentage))
  print('Total key exchange score: {:.2f}%'.format(total_cipher_percentage))
  print('\nTotal score (part 2): {:.2f}%\n'.format(total_security_percentage))

def print_quick():
  final_score, final_grade = grade()
  print('Domain: {}, Grade: {}'.format(hostname, final_grade))

def print_summ():
  print('Domain:', hostname)
  print('Certificate validity checker (40%): {}%'.format(total_cert_percentage))
  print('Security configuration checker (60%): {:.2f}%'.format(total_security_percentage))
  final_score, final_grade = grade()
  print("Total score: {:.2f}%\nGrade: {}".format(final_score, final_grade))

def write_quick():
  final_score, final_grade = grade()
  ofile.write('Domain: {}, Grade: {}\n'.format(hostname, final_grade))

#hostname = 'nur.kz'
#top score 'nur.kz'
#sslv3 'hurriyet.com.tr'
#hostname = input("Domain: ")
if input_file != None:
  with open(input_file) as file:
      input_hostnames = file.read().splitlines()

if output_file != None:
  ofile = open(output_file, 'w')

if input_file != None and output_file != None:
  for i in range(len(input_hostnames)):
    hostname = input_hostnames[i]
    try:
      connect()
      part1_cert_verify()
      part2_security_config()

      if mode == 'full':
        print('Domain:', hostname)
        print_part1()
        print_part2()
        final_score, final_grade = grade()
        print("Total score: {:.2f}%\nGrade: {}".format(final_score, final_grade))
      elif mode == 'summ':
        print_summ()
      elif mode == 'quick':
        print_quick()
        write_quick()
    except:
      print('Domain: {}, Grade: NIL'.format(hostname))
      ofile.write('Domain: {}, Grade: NIL\n'.format(hostname))
else:
  try:
    connect()
    part1_cert_verify()
    part2_security_config()

    if mode == 'full':
      print('Domain:', hostname)
      print_part1()
      print_part2()
      final_score, final_grade = grade()
      print("Total score: {:.2f}%\nGrade: {}".format(final_score, final_grade))
    elif mode == 'summ':
      print_summ()
    elif mode == 'quick':
      print_quick()
  except:
    print('Domain: {}, Grade: NIL'.format(hostname))

if output_file != None:
  ofile.close
