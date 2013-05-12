/*
 * ProFTPD: mod_mime -- provides MIME type detection
 *
 * Copyright (c) 2013 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * This is mod_mime, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * --- DO NOT DELETE BELOW THIS LINE ----
 * $Libraries: -lmagic$
 */

#include "conf.h"
#include "privs.h"

#include "magic.h"

#define MOD_MIME_VERSION	"mod_mime/0.1"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

module mime_module;

static int mime_engine = FALSE;
static int mime_logfd = -1;
static magic_t mime_magic = NULL;
static int magic_flags = MAGIC_SYMLINK|MAGIC_MIME|MAGIC_ERROR;
static array_header *mime_allow_types = NULL, *mime_deny_types = NULL;
static cmd_rec *mime_cmd = NULL;

static const char *trace_channel = "mime";

/* FSIO handlers
 */

static int mime_fsio_write(pr_fh_t *fh, int fd, const char *buf,
    size_t bufsz) {
  int flags;
  const char *desc;

  /* If we have already determined the MIME type, then there's nothing more
   * for us to do.
   */
  if (pr_table_get(mime_cmd->notes, "mod_mime.mime-type", NULL) != NULL) {
    return write(fd, buf, bufsz);
  }

  flags = magic_flags;
  flags &= ~MAGIC_MIME_ENCODING;

  magic_setflags(mime_magic, flags);
  desc = magic_buffer(mime_magic, buf, bufsz);
  magic_setflags(mime_magic, magic_flags);

  if (desc != NULL) {
    size_t desclen;

    (void) pr_log_writefile(mime_logfd, MOD_MIME_VERSION,
      "MIME description for '%s': %s", fh->fh_path, desc);

    desclen = strlen(desc);
    if (pr_table_add(mime_cmd->notes, "mod_mime.mime-type",
        pstrndup(mime_cmd->pool, desc, desclen), desclen + 1) < 0) {
      pr_log_debug(DEBUG0, MOD_MIME_VERSION
        ": %s: error adding 'mod_mime.mime-type' note: %s", mime_cmd->argv[0],
        strerror(errno));
    }

    /* Check the mime type against the allow/deny mime type lists. */
    if (mime_allow_types != NULL) {
      register unsigned int i;
      char **types;
      int allowed = FALSE;

      types = mime_allow_types->elts;
      for (i = 0; i < mime_allow_types->nelts; i++) {
        pr_trace_msg(trace_channel, 8,
          "checking '%s' against MIMEAllowType '%s'", desc, types[i]);
        if (strncasecmp(desc, types[i], desclen + 1) == 0) {
          allowed = TRUE;
          break;
        }
      }

      if (allowed == FALSE) {
        (void) pr_log_writefile(mime_logfd, MOD_MIME_VERSION,
          "MIME type '%s' for '%s' is not in MIMEAllowType list, failing write",
          desc, fh->fh_path);
        errno = EACCES;
        return -1;
      }
    }

    if (mime_deny_types != NULL) {
      register unsigned int i;
      char **types;
      int denied = FALSE;

      types = mime_deny_types->elts;
      for (i = 0; i < mime_deny_types->nelts; i++) {
        pr_trace_msg(trace_channel, 8,
          "checking '%s' against MIMEDenyType '%s'", desc, types[i]);
        if (strncasecmp(desc, types[i], desclen + 1) == 0) {
          denied = TRUE;
          break;
        }
      }

      if (denied == TRUE) {
        (void) pr_log_writefile(mime_logfd, MOD_MIME_VERSION,
          "MIME type '%s' for '%s' is in MIMEDenyType list, failing write",
          desc, fh->fh_path);
        errno = EACCES;
        return -1;
      }
    }

  } else {
    (void) pr_log_writefile(mime_logfd, MOD_MIME_VERSION,
      "unable to determine MIME description for '%s' with %lu bytes: %s",
      fh->fh_path, bufsz, magic_error(mime_magic));
  }

  return write(fd, buf, bufsz); 
}

/* Command handlers
 */

MODRET mime_pre_stor(cmd_rec *cmd) {
  pr_fs_t *fs = NULL;

  if (cmd->argc == 1) {
    return PR_DECLINED(cmd);
  }

  if (mime_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  fs = pr_register_fs(session.pool, "mime", "/");
  if (fs != NULL) {
    config_rec *c;
    const char *best_path;
    xaset_t *dir_ctx;

    fs->write = mime_fsio_write;

    mime_cmd = cmd;

    /* Check for <Directory>-specific MIME{Allow,Deny}Type lists. */
    best_path = dir_best_path(cmd->pool, cmd->arg);
    dir_ctx = get_dir_ctxt(cmd->pool, best_path);

    c = find_config(dir_ctx, CONF_PARAM, "MIMEAllowType", FALSE);
    if (c != NULL) {
      mime_allow_types = c->argv[0];
    }

    c = find_config(dir_ctx, CONF_PARAM, "MIMEDenyType", FALSE);
    if (c != NULL) {
      mime_deny_types = c->argv[0];
    }

  } else {
    (void) pr_log_writefile(mime_logfd, MOD_MIME_VERSION,
      "error registering 'mime' fs: %s", strerror(errno));
  }

  return PR_DECLINED(cmd);
}

MODRET mime_post_stor(cmd_rec *cmd) {
  pr_fs_t *fs = NULL;

  if (cmd->argc == 1) {
    return PR_DECLINED(cmd);
  }

  if (mime_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  fs = pr_unmount_fs("/", "mime");
  if (fs != NULL) {
    destroy_pool(fs->fs_pool);
  }

  /* Reset the allow/deny lists. */
  mime_allow_types = mime_deny_types = NULL;
  mime_cmd = NULL;

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: MIME{Allow,Deny}Type type1 ... typeN */
MODRET set_mimetype(cmd_rec *cmd) {
  register unsigned int i = 0;
  config_rec *c;
  array_header *types;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "missing parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 1, NULL);
  types = make_array(c->pool, 0, sizeof(char *));
  for (i = 1; i < cmd->argc; i++) {
    *((char **) push_array(types)) = pstrdup(c->pool, cmd->argv[i]);
  }
  c->argv[0] = types;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: MIMEEngine on|off */
MODRET set_mimeengine(cmd_rec *cmd) {
  int engine;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  CHECK_ARGS(cmd, 1);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  if (engine == TRUE) {
    mime_engine = TRUE;
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: MIMELog path|"none" */
MODRET set_mimelog(cmd_rec *cmd) {
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  CHECK_ARGS(cmd, 1);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: MIMETable path ... */
MODRET set_mimetable(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  char *tables;

  CHECK_CONF(cmd, CONF_ROOT);

  if (cmd->argc == 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  tables = pstrdup(c->pool, cmd->argv[1]);

  for (i = 2; i < cmd->argc; i++) {
    tables = pstrcat(c->pool, tables, ":", cmd->argv[i], NULL);
  }

  c->argv[0] = tables;
 
  return PR_HANDLED(cmd);
}

/* Event listeners
 */

#ifdef PR_SHARED_MODULE
static void mime_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_mime.c", (char *) event_data) == 0) {
    pr_event_unregister(&mime_module, NULL);
    if (mime_magic != NULL) {
      magic_close(mime_magic);
      mime_magic = NULL;
    }
  }
}
#endif /* PR_SHARED_MODULE */

static void mime_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;
  int flags;

  if (mime_engine == FALSE) {
    return;
  }

  mime_magic = magic_open(flags);
  if (mime_magic == NULL) {
    pr_log_debug(DEBUG0, MOD_MIME_VERSION ": error loading database: %s",
      strerror(errno));
    return;
  }

  pr_log_debug(DEBUG5, MOD_MIME_VERSION ": loaded magic database");

  c = find_config(main_server->conf, CONF_PARAM, "MIMETable", FALSE);
  if (c != NULL) {
    const char *tables;

    tables = c->argv[0];

    pr_log_debug(DEBUG7, MOD_MIME_VERSION
      ": loading additional MIME databases using '%s'", tables);
    if (magic_load(mime_magic, c->argv[0]) < 0) {
      const char *errstr;
      int xerrno = errno;

      errstr = magic_error(mime_magic);
      if (errstr == NULL) {
        errstr = strerror(xerrno); 
      }

      pr_log_debug(DEBUG0, MOD_MIME_VERSION
        ": error loading additional databases '%s': %s", tables, errstr);
    }
  }
}

static void mime_shutdown_ev(const void *event_data, void *user_data) {
  if (mime_magic != NULL) {
    magic_close(mime_magic);
    mime_magic = NULL;
  }
}

/* Initialization functions
 */

static int mime_init(void) {

#ifdef PR_SHARED_MODULE
  pr_event_register(&mime_module, "core.module-unload", mime_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&mime_module, "core.postparse", mime_postparse_ev, NULL);
  pr_event_register(&mime_module, "core.shutdown", mime_shutdown_ev, NULL);

  return 0;
}

static int mime_sess_init(void) {
  config_rec *c;

  if (mime_magic == NULL) {
    return 0;
  }

  mime_engine = FALSE;

  c = find_config(main_server->conf, CONF_PARAM, "MIMEEngine", FALSE);
  if (c != NULL) {
    mime_engine = *((int *) c->argv[0]);
  }

  if (mime_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "MIMELog", FALSE);
  if (c != NULL) {
    char *path;

    path = c->argv[0];

    if (strncasecmp(path, "none", 5) != 0) {
      int res, xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &mime_logfd, 0660);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        pr_log_pri(PR_LOG_NOTICE, MOD_MIME_VERSION
          ": error opening MIMELog '%s': %s", path, strerror(xerrno)); 
      }
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable mime_conftab[] = {
  { "MIMEAllowType",	set_mimetype,		NULL },
  { "MIMEDenyType",	set_mimetype,		NULL },
  { "MIMEEngine",	set_mimeengine,		NULL },
  { "MIMELog",		set_mimelog,		NULL },
  { "MIMETable",	set_mimetable,		NULL },
  { NULL }
};

static cmdtable mime_cmdtab[] = {
  { PRE_CMD,		C_APPE,	G_NONE, mime_pre_stor,	TRUE,	FALSE },
  { PRE_CMD,		C_STOR,	G_NONE, mime_pre_stor,	TRUE,	FALSE },
  { PRE_CMD,		C_STOU,	G_NONE, mime_pre_stor,	TRUE,	FALSE },

  { POST_CMD,		C_APPE,	G_NONE, mime_post_stor,	TRUE,	FALSE },
  { POST_CMD,		C_STOR,	G_NONE, mime_post_stor,	TRUE,	FALSE },
  { POST_CMD,		C_STOU,	G_NONE, mime_post_stor,	TRUE,	FALSE },
  { POST_CMD_ERR,	C_APPE,	G_NONE, mime_post_stor,	TRUE,	FALSE },
  { POST_CMD_ERR,	C_STOR,	G_NONE, mime_post_stor,	TRUE,	FALSE },
  { POST_CMD_ERR,	C_STOU,	G_NONE, mime_post_stor,	TRUE,	FALSE },

  { 0, NULL }
};

module mime_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "mime",

  /* Module configuration handler table */
  mime_conftab,

  /* Module command handler table */
  mime_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  mime_init,

  /* Session initialization function */
  mime_sess_init,

  /* Module version */
  MOD_MIME_VERSION
};
