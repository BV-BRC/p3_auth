#!/usr/bin/env perl

use Module::Build;
Module::Build->new(
    module_name => 'Bio::KBase::Auth',
    license     => 'perl',
    requires => { 'Object::Tiny::RW' => 1.07,
		  'JSON' => 2.53,
		  'Digest::SHA',
		  'Crypt::OpenSSL::RSA',
		  'Convert::PEM' => 0.08,
		  'MIME::Base64' => 3.08,
		  'HTTP::Request' => 6.00,
		  'HTTP::Daemon' => 6.00,
		  'LWP::UserAgent' => 6.02,
		  'LWP::Protocol::https' => 1.0,
		  'URI' => 1.37,
		  'URI::URL' => 1.0,
		  'Test::More' => 0.94,
		  'POSIX' => 1.0,
    },
    dist_abstract => 'Classes to support OAuth based authentication for the Bio::KBase::* libraries',
    )->create_build_script;
