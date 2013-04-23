Gem::Specification.new do |s|
  s.name                     = 'salty_dog'
  s.version                  = '0.1.0'
  s.date                     = '2013-04-21'
  s.summary                  = 'PBKDF2, Ruby-style'
  s.description              = 'A complete, RFC compliant implementation of PBKDF2. As opposed to other PBKDF2 gems, all parameters to the key-derivation function are completely and easily customizable.'
  s.authors                  = ['Brennon Bortz']
  s.email                    = 'brennon@brennonbortz.com'
  s.files                    = ['lib/salty_dog.rb','lib/salty_dog/salty_dog.rb']
  s.require_paths            = ['lib']
  s.homepage                 = 'http://github.com/brennon/salty_dog'
  s.license                  = 'BSD-3'
  s.rdoc_options             = ['--main','README.md']

  s.add_development_dependency 'simplecov', '~> 0.7.1'
  s.add_development_dependency 'turn', '~> 0.9.6'
end

