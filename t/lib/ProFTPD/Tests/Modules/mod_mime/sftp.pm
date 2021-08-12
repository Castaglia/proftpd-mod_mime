package ProFTPD::Tests::Modules::mod_mime::sftp;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use Digest::MD5;
use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;
use POSIX qw(:fcntl_h);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  mime_sftp_upload_text => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_upload_empty => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_upload_binary => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_upload_single_byte => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_allowtype_with_gif => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_allowtype_without_gif => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_allowtype_using_dir => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_allowtype_using_ftpaccess => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_denytype_with_gif => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_denytype_without_gif => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_denytype_using_dir => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

  mime_sftp_config_denytype_using_ftpaccess => {
    order => ++$order,
    test_class => [qw(forking mod_sftp)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }
}

# Support functions

sub create_test_dir {
  my $setup = shift;
  my $sub_dir = shift;

  mkpath($sub_dir);

  # Make sure that, if we're running as root, that the sub directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $sub_dir)) {
      die("Can't set perms on $sub_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $sub_dir)) {
      die("Can't set owner of $sub_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }
}

# Test cases

sub mime_sftp_upload_text {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'fsio:10 mime:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.txt: [$err_name] ($err_code)");
      }

      my $buf = "Farewell, cruel world!\n";
      print $fh $buf;

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      my $expected = 'text/plain';
      $self->assert($mime_type eq $expected,
        test_msg("Expected MIME type '$expected', got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_upload_empty {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.txt: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      $self->assert($mime_type eq '',
        test_msg("Expected no MIME type, got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_upload_binary {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.dat: [$err_name] ($err_code)");
      }

      print $fh $data;

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      my $expected = 'image/gif';
      $self->assert($mime_type eq $expected,
        test_msg("Expected MIME type '$expected', got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_upload_single_byte {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.txt: [$err_name] ($err_code)");
      }

      my $buf;
      vec($buf, 0, 8) = -17;
      print $fh $buf;

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      my $expected = 'application/octet-stream';
      $self->assert($mime_type eq $expected,
        test_msg("Expected MIME type '$expected', got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_allowtype_with_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEAllowType => 'image/gif',
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.dat: [$err_name] ($err_code)");
      }

      print $fh $data;

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      my $expected = 'image/gif';
      $self->assert($mime_type eq $expected,
        test_msg("Expected MIME type '$expected', got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_allowtype_without_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEAllowType => 'text/plain',
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.dat: [$err_name] ($err_code)");
      }

      if ($fh->write($data)) {
        die("WRITE test.dat succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();

      # Assert that we did not actually write any data to the file.
      unless (-f $test_file) {
        die("File $test_file does not exist as expected");
      }

      my $filesz = (stat($test_file))[7];
      $self->assert($filesz == 0, test_msg("Expected 0, got $filesz"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      my $expected = 'image/gif';
      $self->assert($mime_type eq $expected,
        test_msg("Expected MIME type '$expected', got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_allowtype_using_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $sub_dir1 = File::Spec->rel2abs("$tmpdir/test1.d");
  create_test_dir($setup, $sub_dir1);

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  create_test_dir($setup, $sub_dir2);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Directory ~/test1.d>
  MIMEAllowType image/gif
</Directory>

<Directory ~/test2.d>
  MIMEAllowType text/plain
</Directory>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      # We should be able to upload a GIF to test1.d, but not a text file
      my $fh = $sftp->open('test1.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.dat: [$err_name] ($err_code)");
      }

      unless ($fh->write($data)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test1.d/test.dat: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test1.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.txt: [$err_name] ($err_code)");
      }

      my $buf = "Hello, World!\n";
      if ($fh->write($buf)) {
        die("Write to test1.d/test.txt succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef; 

      # We should be able to upload a text file to test2.d, but not a GIF
      $fh = $sftp->open('test2.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.txt: [$err_name] ($err_code)");
      }

      $buf = "Hello, World!\n";
      unless ($fh->write($buf)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test2.d/test.txt: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test2.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.dat: [$err_name] ($err_code)");
      }

      if ($fh->write($data)) {
        die("WRITE test2.d/test.dat succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_allowtype_using_ftpaccess {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $sub_dir1 = File::Spec->rel2abs("$tmpdir/test1.d");
  create_test_dir($setup, $sub_dir1);

  my $ftpaccess_file = File::Spec->rel2abs("$sub_dir1/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh "MIMEAllowType image/gif\n";

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  create_test_dir($setup, $sub_dir2);

  $ftpaccess_file = File::Spec->rel2abs("$sub_dir2/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh "MIMEAllowType text/plain\n";

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'fsio:20 mime:10 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverride => 'on',
    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      # We should be able to upload a GIF to test1.d, but not a text file
      my $fh = $sftp->open('test1.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.dat: [$err_name] ($err_code)");
      }

      unless ($fh->write($data)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test1.d/test.dat: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test1.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.txt: [$err_name] ($err_code)");
      }

      my $buf = "Hello, World!\n";
      if ($fh->write($buf)) {
        die("Write to test1.d/test.txt succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      # We should be able to upload a text file to test2.d, but not a GIF
      $fh = $sftp->open('test2.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.txt: [$err_name] ($err_code)");
      }

      unless ($fh->write($buf)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test2.d/test.txt: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test2.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.dat: [$err_name] ($err_code)");
      }
      
      if ($fh->write($data)) {
        die("Write to test2.d/test.dat succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_denytype_with_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEDenyType => 'image/gif',
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.dat: [$err_name] ($err_code)");
      }

      if ($fh->write($data)) {
        die("Write to test.dat succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      my $expected = 'image/gif';
      $self->assert($mime_type eq $expected,
        test_msg("Expected MIME type '$expected', got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_denytype_without_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEDenyType => 'text/plain',
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $fh = $sftp->open('test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test.dat: [$err_name] ($err_code)");
      }

      unless ($fh->write($data)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test.dat: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# Line: $line\n";
        }

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      my $expected = 'image/gif';
      $self->assert($mime_type eq $expected,
        test_msg("Expected MIME type '$expected', got '$mime_type'"));

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_denytype_using_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $sub_dir1 = File::Spec->rel2abs("$tmpdir/test1.d");
  create_test_dir($setup, $sub_dir1);

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  create_test_dir($setup, $sub_dir2);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Directory ~/test1.d>
  MIMEDenyType image/gif
</Directory>

<Directory ~/test2.d>
  MIMEDenyType text/plain
</Directory>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      # We should be able to upload a text file to test1.d, but not a GIF
      my $fh = $sftp->open('test1.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.txt: [$err_name] ($err_code)");
      }

      my $buf = "Hello, World!\n";
      unless ($fh->write($buf)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test1.d/test.txt: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test1.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.dat: [$err_name] ($err_code)");
      }

      if ($fh->write($data)) {
        die("Write to test1.d/test.dat succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      # We should be able to upload a GIF to test2.d, but not a text file
      $fh = $sftp->open('test2.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.dat: [$err_name] ($err_code)");
      }

      unless ($fh->write($data)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test2.d/test.dat: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test2.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.txt: [$err_name] ($err_code)");
      }   
      
      if ($fh->write($buf)) {
        die("Write to test2.d/test.txt succeeded unexpectedly");
      } 
      
      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub mime_sftp_config_denytype_using_ftpaccess {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $data;

  my $data_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  if (open(my $fh, "< $data_file")) {
    local $/;
    $data = <$fh>;
    close($fh);

  } else {
    die("Can't read $data_file: $!");
  }

  my $sub_dir1 = File::Spec->rel2abs("$tmpdir/test1.d");
  create_test_dir($setup, $sub_dir1);

  my $ftpaccess_file = File::Spec->rel2abs("$sub_dir1/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh "MIMEDenyType image/gif\n";

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  create_test_dir($setup, $sub_dir2);

  $ftpaccess_file = File::Spec->rel2abs("$sub_dir2/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh "MIMEDenyType text/plain\n";

    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:20 sftp:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    AllowOverride => 'on',
    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $setup->{log_file},
        MIMETable => $mime_tab,
      },

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::SSH2;
  my $ex;

  # Ignore SIGPIPE
  local $SIG{PIPE} = sub { };

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(1);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      # We should be able to upload a text file to test1.d, but not a GIF
      my $fh = $sftp->open('test1.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.txt: [$err_name] ($err_code)");
      }

      my $buf = "Hello, World!\n";
      unless ($fh->write($buf)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test1.d/test.txt: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test1.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test1.d/test.dat: [$err_name] ($err_code)");
      }

      if ($fh->write($data)) {
        die("Write to test1.d/test.dat succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      # We should be able to upload a GIF to test2.d, but not a text file
      $fh = $sftp->open('test2.d/test.dat', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.dat: [$err_name] ($err_code)");
      }

      unless ($fh->write($data)) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't write test2.d/test.dat: [$err_name] ($err_code)");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $fh = $sftp->open('test2.d/test.txt', O_WRONLY|O_CREAT, 0644);
      unless ($fh) {
        my ($err_code, $err_name) = $sftp->error();
        die("Can't open test2.d/test.txt: [$err_name] ($err_code)");
      }

      if ($fh->write($buf)) {
        die("Write to test2.d/test.txt succeeded unexpectedly");
      }

      # To issue the FXP_CLOSE, we have to explicit destroy the filehandle
      $fh = undef;

      $sftp = undef;
      $ssh2->disconnect();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
