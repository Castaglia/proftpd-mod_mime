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
  mime_feat_mlst_media_type => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_opts_mlst_media_type => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_mlsd_media_type => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_mlst_media_type => {
    order => ++$order,
    test_class => [qw(forking)],
  },

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
sub mime_feat_mlst_media_type {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->feat();

      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();

      $client->quit();

      my $expected = 211;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      my $expected_feat = ' MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.groupname*;UNIX.mode*;UNIX.owner*;UNIX.ownername*;media-type*;';

      my $found = 0;
      my $nfeat = scalar(@$resp_msgs);
      for (my $i = 0; $i < $nfeat; $i++) {
        if ($resp_msgs->[$i] eq $expected_feat) {
          $found = 1;
          last;
        }
      }

      $self->assert($found, test_msg("Did not see expected '$expected_feat'"));
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

sub mime_opts_mlst_media_type {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);

      my $mime_type_opts = 'modify;perm;size;type;unique;UNIX.group;UNIX.mode;UNIX.owner;';
      my ($resp_code, $resp_msg) = $client->opts("MLST $mime_type_opts");

      my $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'MLST OPTS modify;perm;size;type;unique;UNIX.group;UNIX.mode;UNIX.owner;';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->feat();
      $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();

      $expected = 211;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      my $expected_feat = ' MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.groupname;UNIX.mode*;UNIX.owner*;UNIX.ownername;';

      my $found = 0;
      my $nfeat = scalar(@$resp_msgs);
      for (my $i = 0; $i < $nfeat; $i++) {
        if ($resp_msgs->[$i] eq $expected_feat) {
          $found = 1;
          last;
        }
      }

      $self->assert($found, test_msg("Did not see expected '$expected_feat'"));

      # OPTS MLST to re-enable media-type; confirm via FEAT
      $mime_type_opts = 'modify;perm;size;type;unique;UNIX.group;UNIX.mode;UNIX.owner;media-type;';
      ($resp_code, $resp_msg) = $client->opts("MLST $mime_type_opts");

      $expected = 200;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'MLST OPTS modify;perm;size;type;unique;UNIX.group;UNIX.mode;UNIX.owner;media-type;';
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      $client->feat();
      $resp_code = $client->response_code();
      $resp_msgs = $client->response_msgs();

      $client->quit();

      $expected = 211;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected_feat = ' MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.groupname;UNIX.mode*;UNIX.owner*;UNIX.ownername;media-type*;';

      $found = 0;
      $nfeat = scalar(@$resp_msgs);
      for (my $i = 0; $i < $nfeat; $i++) {
        if ($resp_msgs->[$i] eq $expected_feat) {
          $found = 1;
          last;
        }
      }

      $self->assert($found, test_msg("Did not see expected '$expected_feat'"));
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

sub mime_mlsd_media_type {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $test_dir = File::Spec->rel2abs('t/etc/modules/mod_mime');
  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'facts:20 mime:20',

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});
      $client->type('binary');

      my $conn = $client->mlsd_raw($test_dir);
      unless ($conn) {
        die("Failed to MLSD $test_dir: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Response:\n$buf\n";
      }

      # We have to be careful of the fact that readdir returns directory
      # entries in an unordered fashion.
      my $res = {};
      my $lines = [split(/(\r)?\n/, $buf)];
      foreach my $line (@$lines) {
        if ($line =~ /^modify=\S+;perm=\S+;type=(\S+);unique=\S+;UNIX\.group=\d+;UNIX\.groupname=\S+;UNIX\.mode=\d+;UNIX.owner=\d+;UNIX.ownername=\S+;media-type=(\S+); (.*?)$/) {
          $res->{$3} = $2;
        }
      }

      my $expected = {
        '.' => 'inode/directory',
        '..' => 'inode/directory',
        'magic.mgc' => 'application/octet-stream',
        'RukaiMask.gif' => 'image/gif',
      };

      my $ok = 1;
      my $mismatch = '';
      foreach my $name (keys(%$expected)) {
        unless (defined($res->{$name})) {
          $mismatch = $name;
          $ok = 0;
          last;
        }

        my $mime_type = $res->{$name};
        unless ($mime_type eq $expected->{$name}) {
          $ok = 0;
          last;
        }
      }

      $self->assert($ok,
        test_msg("Expected name '$mismatch' did not match expected pattern in MLSD data"));
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

sub mime_mlst_media_type {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'mime');

  my $test_file = File::Spec->rel2abs('t/etc/modules/mod_mime/RukaiMask.gif');
  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'facts:20 mime:20',

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
      # Allow server to start up
      sleep(1);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client->login($setup->{user}, $setup->{passwd});

      $client->mlst($test_file);
      my $resp_code = $client->response_code();
      my $resp_msgs = $client->response_msgs();
      $client->quit();

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Response:\n";
        foreach my $msg (@$resp_msgs) {
          print STDERR "# $msg\n";
        }
      }

      my $expected = 250;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "modify=\\d+;perm=\\S+;size=2881;type=file;unique=\\S+;UNIX.group=\\d+;UNIX.groupname=\\S+;UNIX.mode=\\S+;UNIX.owner=\\d+;UNIX.ownername=\\S+;media-type=image/gif; $test_file";

      my $ok = 0;
      my $nmsgs = scalar(@$resp_msgs);
      for (my $i = 0; $i < $nmsgs; $i++) {
        if ($resp_msgs->[$i] =~ /$expected/) {
          $ok = 1;
          last;
        }
      }

      $self->assert($ok,
        test_msg("Did not see expected data '$expected' in MLST response '$resp_msgs->[1]'"));
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
      my $mime_type = '';

      while (my $line = <$fh>) {
        chomp($line);

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

      $expected = "Transfer aborted. Operation not permitted";
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
  create_test_dir($setup, $sub_dir1);

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  create_test_dir($setup, $sub_dir2);

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

      $expected = "Transfer aborted. Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # We should be able to upload a text file to test2.d, but not a GIF
      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
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

      $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Operation not permitted";
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

      $expected = "Transfer aborted. Operation not permitted";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # We should be able to upload a text file to test2.d, but not a GIF
      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
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

      $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Operation not permitted";
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

      $expected = "Transfer aborted. Operation not permitted";
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
  create_test_dir($setup, $sub_dir1);

  my $sub_dir2 = File::Spec->rel2abs("$tmpdir/test2.d");
  create_test_dir($setup, $sub_dir2);

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

      $expected = "Transfer aborted. Operation not permitted";
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

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Operation not permitted";
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

      $expected = "Transfer aborted. Operation not permitted";
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

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw('test2.d/test.txt');
      unless ($conn) {
        die("STOR test2.d/test.txt failed: " . $client->response_code() . ' ' .
          $client->response_msg());
      }

      $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();

      $expected = 426;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = "Transfer aborted. Operation not permitted";
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
