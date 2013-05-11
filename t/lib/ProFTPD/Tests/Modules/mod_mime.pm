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

  mime_config_denytype_with_gif => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  mime_config_denytype_without_gif => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
#  return testsuite_get_runnable_tests($TESTS);
  return qw(
    mime_config_denytype_without_gif
  )
}

sub mime_stor_ascii {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub mime_stor_empty {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub mime_stor_binary {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

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
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub mime_stor_single_byte {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $mime_tab = File::Spec->rel2abs('t/etc/modules/mod_mime/magic');

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub mime_config_allowtype_with_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

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
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEAllowType => 'image/gif',
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub mime_config_allowtype_without_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

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
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEAllowType => 'text/plain',
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub mime_config_denytype_with_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

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
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEDenyType => 'image/gif',
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub mime_config_denytype_without_gif {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/mime.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/mime.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/mime.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/mime.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/mime.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

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
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_mime.c' => {
        MIMEDenyType => 'text/plain',
        MIMEEngine => 'on',
        MIMELog => $log_file,
        MIMETable => $mime_tab,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw('test.dat');
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . ' ' .
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
    eval { server_wait($config_file, $rfh) };
    if ($@) { warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  eval {
    if (open(my $fh, "< $log_file")) {
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
      die("Can't read $log_file: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

1;
