package ProFTPD::Tests::Modules::mod_mime;

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
  mime_stor_ascii => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_stor_empty => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_stor_binary => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_stor_single_byte => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_allowtype_with_gif => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_allowtype_without_gif => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_allowtype_using_dir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_allowtype_using_ftpaccess => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_denytype_with_gif => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_denytype_without_gif => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_denytype_using_dir => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_denytype_using_ftpaccess => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub mime_stor_ascii {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Farewell, cruel world!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

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

sub mime_stor_empty {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

        if ($line =~ /MIME description for .*?: (.*)?$/) {
          $mime_type = $1;
          last;
        }
      }

      close($fh);

      $self->assert(!defined($mime_type),
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

sub mime_stor_binary {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

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

sub mime_stor_single_byte {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.txt');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = -17;
      $conn->write($buf, 1, 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

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

sub mime_config_allowtype_with_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

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

sub mime_config_allowtype_without_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

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

sub mime_config_allowtype_using_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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
  mkpath($sub_dir1);

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  mkpath($sub_dir2);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:10',

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      # We should be able to upload a GIF to test1.d, but not a text file
      my $conn = $client->stor_raw('test1.d/test.dat');
      unless ($conn) {
        die("STOR test1.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test1.d/test.txt');
      unless ($conn) {
        die("STOR test1.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # We should be able to upload a text file to test2.d, but not a GIF
      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test2.d/test.dat');
      unless ($conn) {
        die("STOR test2.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
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

sub mime_config_allowtype_using_ftpaccess {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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
  mkpath($sub_dir1);

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
  mkpath($sub_dir2);

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
    Trace => 'mime:10',

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      # We should be able to upload a GIF to test1.d, but not a text file
      my $conn = $client->stor_raw('test1.d/test.dat');
      unless ($conn) {
        die("STOR test1.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test1.d/test.txt');
      unless ($conn) {
        die("STOR test1.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # We should be able to upload a text file to test2.d, but not a GIF
      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test2.d/test.dat');
      unless ($conn) {
        die("STOR test2.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
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

sub mime_config_denytype_with_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

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

sub mime_config_denytype_without_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();
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
      my $mime_type;

      while (my $line = <$fh>) {
        chomp($line);

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

sub mime_config_denytype_using_dir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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
  mkpath($sub_dir1);

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  mkpath($sub_dir2);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'mime:10',

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      # We should be able to upload a text file to test1.d, but not a GIF
      my $conn = $client->stor_raw('test1.d/test.txt');
      unless ($conn) {
        die("STOR test1.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test1.d/test.dat');
      unless ($conn) {
        die("STOR test1.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # We should be able to upload a GIF to test2.d, but not a text file
      $conn = $client->stor_raw('test2.d/test.dat');
      unless ($conn) {
        die("STOR test2.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
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

sub mime_config_denytype_using_ftpaccess {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

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
  mkpath($sub_dir1);

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
  mkpath($sub_dir2);

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
    Trace => 'mime:10',

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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      # We should be able to upload a text file to test1.d, but not a GIF
      my $conn = $client->stor_raw('test1.d/test.txt');
      unless ($conn) {
        die("STOR test1.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test1.d/test.dat');
      unless ($conn) {
        die("STOR test1.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # We should be able to upload a GIF to test2.d, but not a text file
      $conn = $client->stor_raw('test2.d/test.dat');
      unless ($conn) {
        die("STOR test2.d/test.dat failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $conn->write($data, length($data), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      my $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Permission denied";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->quit();
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
