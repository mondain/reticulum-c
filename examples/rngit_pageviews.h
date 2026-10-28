/* The remaining pages of the page server (included by rngit_pages.h's user,
 * reticulum_git.c, after rngit_pages.h): blob, commits, commit, refs, stats,
 * releases, release, work and work document, the counterparts of pages.py's
 * serve_*_page methods. */
#ifndef RETICULUM_C_RNGIT_PAGEVIEWS_H
#define RETICULUM_C_RNGIT_PAGEVIEWS_H

/* os.path.splitext(path)[1].lower() */
static void pg_ext(const char *path, char *out, size_t cap) {
  const char *base = strrchr(path, '/'), *dot, *b;
  size_t i;
  base = base ? base + 1 : path;
  dot = strrchr(base, '.');
  out[0] = 0;
  if (!dot)
    return;
  /* leading dots of the base name do not start an extension */
  b = base;
  while (*b == '.')
    ++b;
  if (dot < b)
    return;
  snprintf(out, cap, "%s", dot);
  for (i = 0; out[i]; ++i)
    if (out[i] >= 'A' && out[i] <= 'Z')
      out[i] = (char)(out[i] + 32);
}
static int pg_is_image_ext(const char *e) {
  static const char *const exts[] = {".webp", ".png", ".jpg", ".jpeg", ".gif", ".tiff", ".tif", ".bmp"};
  size_t i;
  for (i = 0; i < sizeof(exts) / sizeof(exts[0]); ++i)
    if (!strcmp(e, exts[i]))
      return 1;
  return 0;
}
/* the url scope of relative links in a markdown file at file_path */
static void pg_blob_scope(char *out, size_t cap, const char *g, const char *r, const char *ref, const char *file_path) {
  char dir[3100] = "", stripped[3100], *sl;
  pgit_strip_slashes(file_path, stripped, sizeof(stripped));
  sl = strrchr(stripped, '/');
  if (sl)
    snprintf(dir, sizeof(dir), "%.*s/", (int)(sl - stripped), stripped);
  snprintf(out, cap, ":/page/blob.mu`g=%s|r=%s|ref=%s|path=%s", g, r, ref, dir);
}

static void pg_blob_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char file_path[3100], resolved[72], ext[32];
  int render, raw, renderable, convertable;
  sbuf content, nav;
  blob_info bi;
  const char *sep = pg_icon("sep");
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_ref", c.ref, sizeof(c.ref), "HEAD");
  pg_get(rq, "var_path", file_path, sizeof(file_path), "");
  render = pg_truthy(rq, "var_render");
  raw = pg_truthy(rq, "var_raw");
  url_unquote_plus(file_path);
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    m_heading(&content, "Not Found", 1);
    sb_adds(&content, "\n\nThe requested repository does not exist or you do not have access to it.\n");
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  if (!pgit_resolve(c.r->path, c.ref, resolved)) {
    m_heading(&content, "Ref Not Found", 1);
    sb_addf(&content, "\n\nThe ref '%s' does not exist in this repository.\n", c.ref);
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  if (!file_path[0]) {
    m_heading(&content, "Invalid Path", 1);
    sb_adds(&content, "\n\nNo file path specified.\n");
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  {
    char *a = str_replace(file_path[0] == '.' && file_path[1] == '/' ? file_path + 2 : file_path, "/./", "/");
    if (a) {
      snprintf(file_path, sizeof(file_path), "%s", a);
      free(a);
    }
  }
  pg_ext(file_path, ext, sizeof(ext));
  renderable = !strcmp(ext, ".md") || !strcmp(ext, ".mu");
  convertable = !strcmp(ext, ".md");
  if (!renderable) {
    raw = 1;
    render = 0;
  } else if (raw)
    render = 0;
  else if (!render) {
    render = 1;
    raw = 0;
  }
  pg_path_crumbs(&nav, c.gname, c.rname, c.ref, file_path, 0);
  {
    sbuf dl, ctl, mu;
    sb_init(&dl);
    sb_init(&ctl);
    sb_init(&mu);
    pg_link(&dl, 'b', "Download", NULL, "/file/download", "g", c.gname, "r", c.rname, "ref", c.ref, "path", file_path, NULL);
    if (!renderable)
      sb_addf(&nav, "\nDisplaying Raw %s %s\n", sep, sb_str(&dl));
    else {
      if (render) {
        sb_adds(&ctl, "Displaying Rendered ");
        sb_adds(&ctl, sep);
        sb_addc(&ctl, ' ');
        pg_link(&ctl, 'b', "View raw", NULL, "/page/blob.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", file_path, "raw",
                "y", NULL);
      } else {
        sb_adds(&ctl, "Displaying Raw ");
        sb_adds(&ctl, sep);
        sb_addc(&ctl, ' ');
        pg_link(&ctl, 'b', "View rendered", NULL, "/page/blob.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", file_path,
                "render", "y", NULL);
      }
      pg_link(&mu, 'b', "as micron", NULL, "/file/download", "g", c.gname, "r", c.rname, "ref", c.ref, "path", file_path, "fmt",
              "mu", NULL);
      if (convertable)
        sb_addf(&nav, "\n%s %s %s %s%s`f\n", sb_str(&ctl), sep, sb_str(&dl), CLR_DIM, sb_str(&mu));
      else
        sb_addf(&nav, "\n%s %s %s\n", sb_str(&ctl), sep, sb_str(&dl));
    }
    sb_free(&dl);
    sb_free(&ctl);
    sb_free(&mu);
  }
  if (!pgit_blob_info(c.r->path, resolved, file_path, &bi))
    sb_adds(&content, "File not found at this ref.\n");
  else {
    char size_s[32], limit_s[32], hd[4200];
    if (bi.is_tree) {
      sb_free(&content);
      sb_free(&nav);
      pg_tree_page(rq, page);
      return;
    }
    pg_prettysize(size_s, sizeof(size_s), (double)bi.size);
    {
      sbuf sym;
      sb_init(&sym);
      if (bi.is_symlink) {
        sb_adds(&sym, " | Symlink \xe2\x86\x92 ");
        m_escape(&sym, bi.symlink_target[0] ? bi.symlink_target : "unknown");
      }
      snprintf(hd, sizeof(hd), "%s %s%s (%.8s) %s, %s%s`f\n", file_path, CLR_DIM_H, c.ref, resolved,
               bi.is_binary ? "Binary" : "Text", size_s, sb_str(&sym));
      sb_free(&sym);
    }
    m_heading(&content, hd, 2);
    if (bi.is_symlink) {
      sb_adds(&content, "`*");
      m_escape(&content, bi.symlink_target[0] ? bi.symlink_target : "unknown");
      sb_adds(&content, "`*\n");
    } else if (bi.is_binary) {
      if (pg_is_image_ext(ext)) {
        sb_addf(&content, "`(Image file`w=n`a=c`:/media/%s/%s/%s/", c.gname, c.rname, c.ref);
        url_quote_plus(&content, file_path);
        sb_adds(&content, ")\n");
      } else
        sb_adds(&content, "This file appears to be binary and cannot be displayed as text.\n");
    } else if (bi.size > (long long)PG_BLOB_LIMIT) {
      pg_prettysize(limit_s, sizeof(limit_s), (double)PG_BLOB_LIMIT);
      sb_addf(&content, "This file is %s, which exceeds the display limit of %s.\n", size_s, limit_s);
    } else {
      size_t n;
      char *text = pgit_blob_content(c.r->path, resolved, file_path, PG_BLOB_LIMIT + 4096, &n);
      if (text) {
        if (renderable && render) {
          if (!strcmp(ext, ".mu")) {
            py_rstrip(text);
            sb_addf(&content, "%s\n", text);
          } else {
            md_conv mc;
            char scope[3600];
            sbuf conv;
            pg_blob_scope(scope, sizeof(scope), c.gname, c.rname, c.ref, file_path);
            md_init(&mc, PG_MAX_RENDER_WIDTH, scope);
            sb_init(&conv);
            md_format_block(&mc, text, &conv);
            if (conv.p) {
              py_rstrip(conv.p);
              conv.n = strlen(conv.p);
            }
            sb_addf(&content, "%s\n", sb_str(&conv));
            sb_free(&conv);
          }
        } else if (G.highlight_syntax) {
          sbuf hl;
          sb_init(&hl);
          hl_highlight(&hl, text, file_path, NULL);
          if (hl.p) {
            py_rstrip(hl.p);
            hl.n = strlen(hl.p);
          }
          sb_addf(&content, "%s\n", sb_str(&hl));
          sb_free(&hl);
        } else
          sb_addf(&content, "`=\n%s\n`=", text);
        free(text);
      } else
        sb_adds(&content, "Error reading file content.\n");
    }
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "blob", rq->st);
done:
  sb_free(&content);
  sb_free(&nav);
}

static void pg_commits_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char file_path[3100], page_s[32], resolved[72];
  long page_num = 0;
  sbuf content, nav;
  commit_row *rows = NULL;
  size_t n = 0, i;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_ref", c.ref, sizeof(c.ref), "HEAD");
  pg_get(rq, "var_path", file_path, sizeof(file_path), "");
  url_unquote_plus(file_path);
  pg_get(rq, "var_page", page_s, sizeof(page_s), "0");
  {
    char *end, *s = py_strip(page_s);
    page_num = strtol(s, &end, 10);
    if (end == s || *end || page_num < 0)
      page_num = 0;
    if (page_num > 1000000)
      page_num = 1000000;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    m_heading(&content, "Not Found", 1);
    sb_adds(&content, "\n\nThe requested repository does not exist or you do not have access to it.\n");
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  if (!pgit_resolve(c.r->path, c.ref, resolved)) {
    m_heading(&content, "Ref Not Found", 1);
    sb_addf(&content, "\n\nThe ref '%s' does not exist in this repository.\n", c.ref);
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
  sb_adds(&nav, " / ");
  if (file_path[0]) {
    m_escape(&nav, file_path);
    sb_adds(&nav, " / ");
  }
  sb_adds(&nav, "commits\n");
  if (!pgit_commits(c.r->path, resolved, file_path, (unsigned long)page_num * PG_COMMITS_PER_PAGE, PG_COMMITS_PER_PAGE, &rows,
                    &n))
    sb_adds(&content, "Error reading commit history.\n");
  else if (!n)
    sb_adds(&content, "No commits found.\n");
  else {
    sbuf h;
    sb_init(&h);
    sb_addf(&h, "Commits%s%s %s%s (%.8s)`f", file_path[0] ? " for " : "", file_path, CLR_DIM_H, c.ref, resolved);
    m_heading(&content, sb_str(&h), 2);
    sb_free(&h);
    sb_addc(&content, '\n');
    for (i = 0; i < n; ++i) {
      char date_a[64], date_r[96], shortx[8];
      pg_fmt_localtime(date_a, sizeof(date_a), (double)rows[i].timestamp, "%Y-%m-%d %H:%M:%S");
      pg_relative_time(date_r, sizeof(date_r), (double)rows[i].timestamp);
      sb_adds(&content, "`F66d");
      snprintf(shortx, sizeof(shortx), "%.7s", rows[i].hash);
      pg_link(&content, 'b', shortx, NULL, "/page/commit.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "h", rows[i].hash, NULL);
      sb_adds(&content, "`f ");
      m_escape(&content, rows[i].author);
      sb_addf(&content, " %s%s - %s`f\n", CLR_DIM, date_a, date_r);
      m_escape(&content, rows[i].subject);
      sb_adds(&content, "\n\n");
    }
    {
      int has_more = n == PG_COMMITS_PER_PAGE;
      if (page_num > 0 || has_more) {
        if (page_num > 0) {
          pg_link(&content, 'b', "\xc2\xab Newer", NULL, "/page/commits.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path",
                  file_path, "page", pg_itoa(page_num - 1), NULL);
          sb_adds(&content, " | ");
        }
        sb_addf(&content, "Page %ld", page_num + 1);
        if (has_more) {
          sb_adds(&content, " | ");
          pg_link(&content, 'b', "Older \xc2\xbb", NULL, "/page/commits.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path",
                  file_path, "page", pg_itoa(page_num + 1), NULL);
        }
        sb_addc(&content, '\n');
      }
    }
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "commits", rq->st);
done:
  pgit_commits_free(rows, n);
  sb_free(&content);
  sb_free(&nav);
}

/* format_diff (is_diff) / format_commit: the text with backslashes doubled,
 * then each line marked up */
static void pg_format_diff(sbuf *o, const char *diff, int is_diff) {
  char *esc = str_replace(diff, "\\", "\\\\"), *line, *next;
  int first = 1;
  if (!esc)
    return;
#define PG_NL() \
  do {          \
    if (!first) \
      sb_addc(o, '\n'); \
    first = 0;  \
  } while (0)
  for (line = esc; line; line = next) {
    char *nl = strchr(line, '\n');
    if (nl) {
      *nl = 0;
      next = nl + 1;
    } else
      next = NULL;
    if (!is_diff) {
      PG_NL();
      if (line[0] == '-')
        sb_addc(o, '\\');
      m_escape(o, line);
    } else if (line[0] == '+') {
      PG_NL();
      if (starts_with(line, "+++"))
        m_escape(o, line);
      else {
        sb_adds(o, CLR_DIFF_A);
        m_escape(o, line);
        sb_adds(o, "`f");
      }
    } else if (line[0] == '-') {
      PG_NL();
      if (starts_with(line, "---")) {
        sb_addc(o, '\\');
        m_escape(o, line);
      } else {
        sb_adds(o, CLR_DIFF_R);
        m_escape(o, line);
        sb_adds(o, "`f");
      }
    } else if (starts_with(line, "@@")) {
      PG_NL();
      sb_adds(o, CLR_DIFF_P);
      m_escape(o, line);
      sb_adds(o, "`f");
    } else if (starts_with(line, "diff ") || starts_with(line, "index ") || starts_with(line, "new file") ||
               starts_with(line, "deleted file")) {
      if (starts_with(line, "diff --git a"))
        PG_NL();
      PG_NL();
      sb_adds(o, CLR_DIM);
      m_escape(o, line);
      sb_adds(o, "`f");
    } else {
      PG_NL();
      m_escape(o, line);
    }
  }
#undef PG_NL
  free(esc);
}

static void pg_commit_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char commit_hash[1024], resolved[72], rhash[72];
  sbuf content, nav;
  commit_info ci;
  int have_ci = 0;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_ref", c.ref, sizeof(c.ref), "HEAD");
  pg_get(rq, "var_h", commit_hash, sizeof(commit_hash), "");
  if (!c.gname[0] || !c.rname[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested repository was not found.\n", NULL, NULL);
    goto done;
  }
  if (!pgit_resolve(c.r->path, c.ref, resolved)) {
    m_heading(&content, "Ref Not Found", 1);
    sb_addf(&content, "\n\nThe ref '%s' does not exist in this repository.\n", c.ref);
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  if (strlen(commit_hash) < 7) {
    pg_error_page(rq, page, "Error", 2, "\nNo valid commit hash specified.\n", NULL, NULL);
    goto done;
  }
  if (!pgit_resolve(c.r->path, commit_hash, rhash)) {
    char body[1300];
    snprintf(body, sizeof(body), "\nThe commit %s does not exist in this repository.\n", commit_hash);
    pg_error_page(rq, page, "Error", 2, body, NULL, NULL);
    goto done;
  }
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', "commits", NULL, "/page/commits.mu", "g", c.gname, "r", c.rname, "ref", c.ref, NULL);
  sb_addf(&nav, " / %.7s\n", rhash);
  {
    char *argv[] = {"git", "cat-file", "-t", rhash, NULL}, *type = NULL;
    int ok = pgit_run(c.r->path, argv, &type, 64, NULL) && !strcmp(py_strip(type), "commit");
    free(type);
    if (!ok) {
      char body[1300];
      snprintf(body, sizeof(body), "\nThe hash %s does not refer to a commit.\n", commit_hash);
      pg_error_page(rq, page, "Error", 2, body, NULL, NULL);
      goto done;
    }
  }
  have_ci = pgit_commit_info(c.r->path, rhash, &ci);
  if (!have_ci) {
    m_heading(&content, "Error", 2);
    sb_adds(&content, "\n\nCould not retrieve commit information.\n");
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  {
    sbuf h;
    char lbl[128];
    sig_status sg;
    int show_sig = 0;
    char sig_text[700];
    size_t i;
    sb_init(&h);
    sb_addf(&h, "Commit %s", rhash);
    m_heading(&content, sb_str(&h), 2);
    sb_free(&h);
    sb_addc(&content, '\n');
    snprintf(lbl, sizeof(lbl), "%s Browse tree at this commit", pg_icon("folder"));
    pg_link(&content, 'b', lbl, NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", rhash, NULL);
    sb_adds(&content, "\n\n");
    pgit_commit_signature(c.r->path, rhash, &sg);
    if (sg.is_signed) {
      sbuf e;
      sb_init(&e);
      m_escape(&e, sg.message);
      if (sg.valid && sg.author_match)
        snprintf(sig_text, sizeof(sig_text), "`FT66BB85Valid, signed by author`f");
      else if (sg.valid)
        snprintf(sig_text, sizeof(sig_text), "`Faa0%s`f", sb_str(&e));
      else
        snprintf(sig_text, sizeof(sig_text), "`F900%s`f", sb_str(&e));
      sb_free(&e);
      show_sig = 1;
    }
    if (ci.nparents) {
      sb_adds(&content, "Parents    : ");
      for (i = 0; i < ci.nparents; ++i) {
        char shortx[8];
        snprintf(shortx, sizeof(shortx), "%.7s", ci.parents[i]);
        if (i)
          sb_addc(&content, ' ');
        pg_link(&content, 'b', shortx, NULL, "/page/commit.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "h", ci.parents[i], NULL);
      }
      sb_addc(&content, '\n');
    }
    sb_adds(&content, "Author     : ");
    m_escape(&content, ci.author_name);
    sb_adds(&content, " <");
    m_escape(&content, ci.author_email);
    sb_adds(&content, ">\n");
    if (show_sig)
      sb_addf(&content, "Signature  : %s\n", sig_text);
    sb_addf(&content, "Date       : %s\n", ci.author_date);
    if (strcmp(ci.committer_name, ci.author_name)) {
      sb_adds(&content, "Committer : ");
      m_escape(&content, ci.committer_name);
      sb_adds(&content, " <");
      m_escape(&content, ci.committer_email);
      sb_adds(&content, ">\n");
      sb_addf(&content, "Date      : %s\n", ci.committer_date);
    }
    sb_addc(&content, '\n');
    if (ci.message && ci.message[0]) {
      pg_format_diff(&content, ci.message, 0);
      sb_adds(&content, "\n\n");
    }
    if (ci.nfiles) {
      long adds = 0, dels = 0;
      for (i = 0; i < ci.nfiles; ++i) {
        adds += ci.files[i].additions;
        dels += ci.files[i].deletions;
      }
      m_heading(&content, "Changes", 2);
      sb_addc(&content, '\n');
      sb_addf(&content, "  %zu files changed, %ld insertions(+), %ld deletions(-)\n\n", ci.nfiles, adds, dels);
      for (i = 0; i < ci.nfiles; ++i) {
        const file_change *f = &ci.files[i];
        sbuf lab;
        char st[40];
        switch (f->status) {
        case 'A': snprintf(st, sizeof(st), "`F0a0A`f"); break;
        case 'D': snprintf(st, sizeof(st), "`F900D`f"); break;
        case 'M': snprintf(st, sizeof(st), "`Faa0M`f"); break;
        case 'R': snprintf(st, sizeof(st), "`F0aaR`f"); break;
        default: snprintf(st, sizeof(st), "%c", f->status);
        }
        sb_init(&lab);
        m_escape(&lab, f->path);
        sb_addf(&content, "  %s ", st);
        pg_link(&content, 'b', sb_str(&lab), NULL, "/page/blob.mu", "g", c.gname, "r", c.rname, "ref", rhash, "path", f->path, NULL);
        sb_addc(&content, ' ');
        if (f->additions > 0) {
          sb_addf(&content, "`F0a0+%ld`f", f->additions);
          if (f->deletions > 0)
            sb_addc(&content, ' ');
        }
        if (f->deletions > 0)
          sb_addf(&content, "`F900-%ld`f", f->deletions);
        sb_addc(&content, '\n');
        sb_free(&lab);
      }
      sb_addc(&content, '\n');
    }
    if (ci.diff && ci.diff[0]) {
      sbuf d;
      const char *s;
      m_heading(&content, "Diff", 2);
      sb_addc(&content, '\n');
      sb_init(&d);
      pg_format_diff(&d, ci.diff, 1);
      s = d.p ? d.p : "";
      while (is_space_c(*s))
        ++s;
      sb_adds(&content, s);
      sb_free(&d);
    }
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "commit", rq->st);
done:
  if (have_ci)
    pgit_commit_info_free(&ci);
  sb_free(&content);
  sb_free(&nav);
}

static void pg_refs_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char ref_type[64], default_branch[512] = "";
  int has_default = 0, show_heads, show_tags;
  sbuf content, nav;
  refs_info ri;
  size_t i;
  const char *sep = pg_icon("sep");
  memset(&ri, 0, sizeof(ri));
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_type", ref_type, sizeof(ref_type), "");
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
  sb_adds(&nav, " / refs\n");
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  if (!c.gname[0] || !c.rname[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested repository was not found.\n", sb_str(&nav), NULL);
    goto done;
  }
  pg_link(&content, 'b', "All", NULL, "/page/refs.mu", "g", c.gname, "r", c.rname, NULL);
  sb_addf(&content, " %s ", sep);
  pg_link(&content, 'b', "Branches only", NULL, "/page/refs.mu", "g", c.gname, "r", c.rname, "type", "heads", NULL);
  sb_addf(&content, " %s ", sep);
  pg_link(&content, 'b', "Tags only", NULL, "/page/refs.mu", "g", c.gname, "r", c.rname, "type", "tags", NULL);
  sb_adds(&content, "\n\n");
  {
    char *argv[] = {"git", "symbolic-ref", "HEAD", NULL}, *text;
    if (pgit_run(c.r->path, argv, &text, 1024, NULL)) {
      char *res = str_replace(py_strip(text), "refs/heads/", "");
      if (res) {
        snprintf(default_branch, sizeof(default_branch), "%s", res);
        free(res);
        has_default = 1;
      }
      free(text);
    }
  }
  show_heads = !ref_type[0] || !strcmp(ref_type, "heads");
  show_tags = !ref_type[0] || !strcmp(ref_type, "tags");
  pgit_refs_info(c.r->path, has_default ? default_branch : NULL, &ri);
  if (show_heads && ri.nheads) {
    sbuf h;
    sb_init(&h);
    sb_addf(&h, "Branches (%zu)", ri.nheads);
    m_heading(&content, sb_str(&h), 2);
    sb_free(&h);
    sb_addc(&content, '\n');
    for (i = 0; i < ri.nheads; ++i) {
      const ref_row *x = &ri.heads[i];
      if (x->is_default)
        sb_addf(&content, "`F0a0%s`f `F0a0(default)`f", x->name);
      else
        sb_adds(&content, x->name);
      sb_adds(&content, " [");
      pg_link(&content, 'b', "tree", NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", x->name, NULL);
      sb_adds(&content, "] [");
      pg_link(&content, 'b', "commits", NULL, "/page/commits.mu", "g", c.gname, "r", c.rname, "ref", x->name, NULL);
      sb_adds(&content, "]\n");
      sb_addf(&content, "%s: ", x->short_hash);
      m_escape(&content, x->subject);
      sb_adds(&content, "\n\n");
    }
  }
  if (show_tags && ri.ntags) {
    sbuf h;
    sb_init(&h);
    sb_addf(&h, "Tags (%zu)", ri.ntags);
    m_heading(&content, sb_str(&h), 2);
    sb_free(&h);
    sb_addc(&content, '\n');
    for (i = ri.ntags; i-- > 0;) {
      const ref_row *x = &ri.tags[i];
      sb_adds(&content, x->name);
      if (x->is_annotated)
        sb_adds(&content, " `Faa0(annotated)`f");
      sb_addf(&content, " %s%s`f [", CLR_DIM, x->short_hash);
      pg_link(&content, 'b', "tree", NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", x->name, NULL);
      sb_adds(&content, "] [");
      pg_link(&content, 'b', "commits", NULL, "/page/commits.mu", "g", c.gname, "r", c.rname, "ref", x->name, NULL);
      sb_adds(&content, "]\n");
      if (x->is_annotated && x->tag_message && x->tag_message[0]) {
        size_t cut = u8_prefix(x->tag_message, 512);
        char *m = md_dup(x->tag_message, cut);
        if (m) {
          m_escape(&content, m);
          free(m);
        }
        sb_adds(&content, "\n\n");
      } else {
        m_escape(&content, x->subject);
        sb_adds(&content, "\n\n");
      }
    }
  }
  if (show_heads && !ri.nheads && show_tags && !ri.ntags)
    sb_adds(&content, "No refs found in this repository.\n");
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  {
    sbuf fin;
    sb_init(&fin);
    if (content.p) {
      py_rstrip(content.p);
      content.n = strlen(content.p);
    }
    sb_addf(&fin, "%s\n", sb_str(&content));
    pg_render(page, sb_str(&fin), sb_str(&nav), "refs", rq->st);
    sb_free(&fin);
  }
done:
  pgit_refs_free(&ri);
  sb_free(&content);
  sb_free(&nav);
}

static void pg_stats_page(pgreq *rq, sbuf *page) {
  pgctx c;
  sbuf content, nav;
  repo_stats *s = NULL;
  static const char *const level_name[4] = {"inactive", "low", "moderate", "high"};
  static const char *const level_color[4] = {"`F666", "`F66d", "`Faa0", "`F0a0"};
  static const char *const level_label[4] = {"No activity", "Low activity", "Moderate activity", "High activity"};
  const char *act_color = "`F666", *act_label = "Unknown";
  int lv;
  unsigned long long v_tday, f_tday, p_tday, d_tday;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  if (!c.gname[0] || !c.rname[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
  sb_adds(&nav, " / stats\n");
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r || !pg_perm(rq, c.g, c.r, P_STATS)) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested repository was not found.\n", sb_str(&nav), NULL);
    goto done;
  }
  s = malloc(sizeof(*s));
  if (!s || !repository_stats(pg_eff(rq), c.g, c.r, 90, pg_now(), s)) {
    pg_error_page(rq, page, "Stats Unavailable", 2, "\nCould not retrieve statistics for this repository.\n", sb_str(&nav), NULL);
    goto done;
  }
  for (lv = 0; lv < 4; ++lv)
    if (!strcmp(s->activity_level, level_name[lv])) {
      act_color = level_color[lv];
      act_label = level_label[lv];
    }
  {
    char hd[600];
    snprintf(hd, sizeof(hd), "Stats for %s", c.rname);
    m_heading(&content, hd, 2);
  }
  v_tday = s->daily[RS_VIEWS][s->lookback - 1];
  f_tday = s->daily[RS_FETCHES][s->lookback - 1];
  p_tday = s->daily[RS_PUSHES][s->lookback - 1];
  d_tday = s->daily[RS_COMBINED][s->lookback - 1];
  sb_addf(&content, "\n`FT%sFetches`f   : %5llu  total %s  today: %3llu  peak: %3llu \n`f", RCLR_FETCH, s->total[RS_FETCHES], CLR_DIM,
          f_tday, s->peak[RS_FETCHES]);
  sb_addf(&content, "`FT%sPushes`f    : %5llu  total %s  today: %3llu  peak: %3llu \n`f", RCLR_PUSH, s->total[RS_PUSHES], CLR_DIM,
          p_tday, s->peak[RS_PUSHES]);
  sb_addf(&content, "`FT%sViews`f     : %5llu  total %s  today: %3llu  peak: %3llu `f\n", RCLR_VIEW, s->total[RS_VIEWS], CLR_DIM,
          v_tday, s->peak[RS_VIEWS]);
  sb_addf(&content, "`FT%sDownloads`f : %5llu  total %s  today: %3llu  peak: %3llu `f\n", RCLR_DOWNLOAD, s->total[RS_COMBINED],
          CLR_DIM, d_tday, s->peak[RS_COMBINED]);
  sb_addf(&content, "`F0aaActivity`f  : %5d points\n\n", s->activity_score);
  sb_addf(&content, "%s%s`f over the last %d days (%s)\n\n", act_color, act_label, s->actual_days, s->date_range);
  {
    char first[32];
    snprintf(first, sizeof(first), "%d days ago", s->lookback);
    if (s->total[RS_FETCHES] > 0) {
      m_heading(&content, "Fetches", 2);
      sb_addc(&content, '\n');
      pg_render_chart(&content, s->daily[RS_FETCHES], s->lookback, first, "Today", RCLR_FETCH, RCLR_FETCH_G, 0);
      sb_addc(&content, '\n');
    }
    if (s->total[RS_PUSHES] > 0) {
      m_heading(&content, "Pushes", 2);
      sb_addc(&content, '\n');
      pg_render_chart(&content, s->daily[RS_PUSHES], s->lookback, first, "Today", RCLR_PUSH, RCLR_PUSH_G, 0);
      sb_addc(&content, '\n');
    }
    if (s->total[RS_VIEWS] > 0) {
      m_heading(&content, "Views", 2);
      sb_addc(&content, '\n');
      pg_render_chart(&content, s->daily[RS_VIEWS], s->lookback, first, "Today", RCLR_VIEW, RCLR_VIEW_G, 0);
      sb_addc(&content, '\n');
    }
    if (s->total[RS_COMBINED] > 0) {
      m_heading(&content, "Downloads", 2);
      sb_addc(&content, '\n');
      pg_render_chart(&content, s->daily[RS_COMBINED], s->lookback, first, "Today", RCLR_DOWNLOAD, RCLR_DOWNLOAD_G, 1.7);
      sb_addc(&content, '\n');
    }
    if (s->activity_score > 0) {
      m_heading(&content, "Combined Activity", 2);
      sb_addc(&content, '\n');
      pg_render_combined(&content, s, first, "Today");
    } else
      m_italic(&content, "\nNo development activity recorded for this repository in the selected time period.\n\n");
  }
  pg_render(page, sb_str(&content), sb_str(&nav), "stats", rq->st);
done:
  free(s);
  sb_free(&content);
  sb_free(&nav);
}

static void pg_releases_page(pgreq *rq, sbuf *page) {
  pgctx c;
  sbuf content, nav;
  char rpath[PATH_MAX + 16], latest[256];
  pg_rel *rels = NULL;
  size_t n = 0, i, published = 0;
  const char *sep = pg_icon("sep");
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  if (!c.gname[0] || !c.rname[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested repository was not found.\n", NULL, NULL);
    goto done;
  }
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
  sb_adds(&nav, " / releases\n");
  snprintf(rpath, sizeof(rpath), "%s.releases", c.r->path);
  rels = pg_releases(rpath, &n, latest, sizeof(latest));
  if (!n) {
    m_heading(&content, "Releases", 2);
    sb_adds(&content, "\nNo releases available for this repository.\n");
    pg_render(page, sb_str(&content), sb_str(&nav), "repo", rq->st);
    goto done;
  }
  for (i = 0; i < n; ++i)
    if (!strcmp(rels[i].status, "published"))
      ++published;
  {
    char h[64];
    snprintf(h, sizeof(h), "Releases (%zu)", published);
    m_heading(&content, h, 2);
  }
  sb_addc(&content, '\n');
  for (i = 0; i < n; ++i) {
    const pg_rel *x = &rels[i];
    char date_s[32];
    if (strcmp(x->status, "published"))
      continue;
    if (x->created)
      pg_fmt_localtime(date_s, sizeof(date_s), (double)x->created, "%Y-%m-%d");
    else
      snprintf(date_s, sizeof(date_s), "unknown");
    pg_link(&content, 'b', x->tag, NULL, "/page/release.mu", "g", c.gname, "r", c.rname, "t", x->tag, NULL);
    sb_addf(&content, " %s%s %s `*%d artifact%s`*", CLR_DIM, date_s, sep, x->artifacts, x->artifacts != 1 ? "s" : "");
    if (!strcmp(x->tag, latest))
      sb_addf(&content, " %s %s`*Latest`*`f", sep, CLR_OK_DIM);
    sb_adds(&content, "`f\n");
    if (x->preview[0]) {
      char prev[2200];
      size_t cut = u8_prefix(x->preview, 2048);
      int truncated = x->preview[cut] != 0;
      snprintf(prev, sizeof(prev), "%.*s%s", (int)cut, x->preview, truncated ? "\xe2\x80\xa6" : "");
      if (!strcmp(x->format, "markdown")) {
        md_conv mc;
        md_init(&mc, PG_MAX_RENDER_WIDTH, NULL);
        md_format_block(&mc, prev, &content);
        sb_addc(&content, '\n');
      } else if (!strcmp(x->format, "micron"))
        sb_addf(&content, "%s\n", prev);
      else {
        m_escape(&content, prev);
        sb_addc(&content, '\n');
      }
    }
    sb_addc(&content, '\n');
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  {
    sbuf fin;
    sb_init(&fin);
    if (content.p) {
      py_rstrip(content.p);
      content.n = strlen(content.p);
    }
    sb_addf(&fin, "%s\n", sb_str(&content));
    pg_render(page, sb_str(&fin), sb_str(&nav), "releases", rq->st);
    sb_free(&fin);
  }
done:
  free(rels);
  sb_free(&content);
  sb_free(&nav);
}

/* "\r\n" and "\r" become "\n", as Python's text mode reads do */
static void pg_universal_newlines(char *s) {
  char *w = s;
  for (; *s; ++s) {
    if (*s == '\r') {
      *w++ = '\n';
      if (s[1] == '\n')
        ++s;
    } else
      *w++ = *s;
  }
  *w = 0;
}
/* "latest" becomes the latest published tag (or the most recently created
 * release when there is none); returns 0 with *why when nothing exists */
static int pg_resolve_tag(const char *releases_path, char *tag, size_t cap, const char **why) {
  pg_rel *rels;
  size_t n, i;
  char latest[256];
  if (strcmp(tag, "latest"))
    return 1;
  rels = pg_releases(releases_path, &n, latest, sizeof(latest));
  if (!n) {
    free(rels);
    if (why)
      *why = "\nNo releases exist.\n";
    return 0;
  }
  if (!latest[0]) {
    long long best = -1;
    for (i = 0; i < n; ++i)
      if (rels[i].created > best) {
        best = rels[i].created;
        snprintf(tag, cap, "%s", rels[i].tag);
      }
  } else
    snprintf(tag, cap, "%s", latest);
  free(rels);
  return 1;
}
static void pg_release_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char tag[300], rpath[PATH_MAX + 16], release_dir[PATH_MAX * 2 + 8];
  sbuf content, nav;
  meta m;
  const char *sep = pg_icon("sep"), *why = NULL;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_t", tag, sizeof(tag), "");
  if (!c.gname[0] || !c.rname[0] || !tag[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested repository was not found.\n", NULL, NULL);
    goto done;
  }
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', "releases", NULL, "/page/releases.mu", "g", c.gname, "r", c.rname, NULL);
  sb_addf(&nav, " / %s\n", tag);
  snprintf(rpath, sizeof(rpath), "%s.releases", c.r->path);
  if (!pg_resolve_tag(rpath, tag, sizeof(tag), &why)) {
    pg_error_page(rq, page, "Release Not Found", 2, why, sb_str(&nav), NULL);
    goto done;
  }
  snprintf(release_dir, sizeof(release_dir), "%s/%s", rpath, tag);
  if (!plain_name(tag) || !is_dir(release_dir)) {
    char body[400];
    snprintf(body, sizeof(body), "\nThe release %.250s does not exist.\n", tag);
    pg_error_page(rq, page, "Release Not Found", 2, body, sb_str(&nav), NULL);
    goto done;
  }
  if (!meta_read(release_dir, &m)) {
    pg_error_page(rq, page, "Error", 2, "\nCould not load release data.\n", sb_str(&nav), NULL);
    goto done;
  }
  if (strcmp(m.status[0] ? m.status : "unknown", "published")) {
    char body[400];
    snprintf(body, sizeof(body), "\nThe release %.250s does not exist.\n", tag);
    pg_error_page(rq, page, "Release Not Found", 2, body, sb_str(&nav), NULL);
    goto done;
  }
  {
    char key[PATH_MAX * 2 + 16], buf[128], adir[PATH_MAX * 2 + 16];
    long thanks_count;
    char *notes = malloc(256u << 10);
    int fmt_md = 0, have_notes = 0;
    pg_art *arts = NULL;
    size_t na = 0, i;
    DIR *d;
    struct dirent *e;
    snprintf(key, sizeof(key), "%s/THANKS", release_dir);
    thanks_count = pg_thanks(key, pg_truthy(rq, "var_thanks"), rq->link_id, release_dir);
    snprintf(buf, sizeof(buf), "%s Thanks (%ld)", pg_icon("heart"), thanks_count);
    pg_link(&content, 'r', buf, NULL, "/page/release.mu", "g", c.gname, "r", c.rname, "t", tag, "thanks", "y", NULL);
    sb_adds(&content, "\n\n");
    {
      char hd[400], ts[96] = "";
      if (m.created) {
        char t2[48];
        pg_fmt_localtime(t2, sizeof(t2), (double)m.created, "%Y-%m-%d %H:%M:%S");
        snprintf(ts, sizeof(ts), " %s %s", sep, t2);
      }
      snprintf(hd, sizeof(hd), "Release %s%s", tag, ts);
      m_heading(&content, hd, 2);
    }
    sb_addc(&content, '\n');
    if (notes) {
      static const char *const nn[2] = {"RELEASE.md", "RELEASE.mu"};
      for (i = 0; i < 2; ++i) {
        char np[PATH_MAX * 2 + 32];
        snprintf(np, sizeof(np), "%s/%s", release_dir, nn[i]);
        if (is_file(np)) {
          read_small(np, notes, 256u << 10);
          pg_universal_newlines(notes);
          fmt_md = i == 0;
          have_notes = notes[0] != 0;
          break;
        }
      }
      if (have_notes) {
        if (fmt_md) {
          md_conv mc;
          md_init(&mc, PG_MAX_RENDER_WIDTH, NULL);
          md_format_block(&mc, notes, &content);
        } else
          sb_adds(&content, notes);
        sb_adds(&content, "\n\n");
      }
      free(notes);
    }
    snprintf(adir, sizeof(adir), "%s/artifacts", release_dir);
    d = opendir(adir);
    if (d) {
      arts = calloc(512, sizeof(pg_art));
      while (arts && (e = readdir(d)) != NULL && na < 512) {
        char full[PATH_MAX * 2 + 32];
        struct stat st;
        snprintf(full, sizeof(full), "%s/%s", adir, e->d_name);
        if (!stat(full, &st) && S_ISREG(st.st_mode)) {
          snprintf(arts[na].name, sizeof(arts[na].name), "%s", e->d_name);
          arts[na].size = (long long)st.st_size;
          ++na;
        }
      }
      closedir(d);
    }
    if (na) {
      char hd[64];
      qsort(arts, na, sizeof(pg_art), pg_art_cmp);
      snprintf(hd, sizeof(hd), "Artifacts (%zu)", na);
      m_heading(&content, hd, 2);
      sb_addc(&content, '\n');
      for (i = 0; i < na; ++i) {
        sbuf l1;
        char l2[64], sz[32];
        pg_prettysize(sz, sizeof(sz), (double)arts[i].size);
        sb_init(&l1);
        sb_addf(&l1, "%s ", pg_icon("file"));
        m_escape(&l1, arts[i].name);
        snprintf(l2, sizeof(l2), "(%s)", sz);
        pg_link(&content, 'r', sb_str(&l1), NULL, "/file/artifact", "g", c.gname, "r", c.rname, "t", tag, "a", arts[i].name, NULL);
        sb_addc(&content, ' ');
        sb_adds(&content, CLR_DIM);
        pg_link(&content, 'r', l2, NULL, "/file/artifact", "g", c.gname, "r", c.rname, "t", tag, "a", arts[i].name, NULL);
        sb_adds(&content, "`f\n");
        sb_free(&l1);
      }
    } else {
      m_heading(&content, "Artifacts", 2);
      sb_adds(&content, "\n`*No artifacts for this release`*\n");
    }
    free(arts);
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "release", rq->st);
done:
  sb_free(&content);
  sb_free(&nav);
}

/* ---- work documents --------------------------------------------------------- */
/* "<hex>" of a 16 byte author field */
static int pg_hex_author(const val *meta, char *out, size_t cap) {
  const val *a = map_get(meta, "author");
  size_t i;
  if (!a || a->type != V_BIN || !a->n || cap < a->n * 2 + 4)
    return 0;
  out[0] = '<';
  for (i = 0; i < a->n; ++i)
    snprintf(out + 1 + 2 * i, 3, "%02x", a->p[i]);
  out[1 + 2 * a->n] = '>';
  out[2 + 2 * a->n] = 0;
  return 1;
}
typedef struct pg_wdoc {
  long id;
  char title[2048], author[100];
  double created, edited;
  long comments;
} pg_wdoc;
/* newest first (key: the later of created and edited) */
static int pg_wdoc_before(const pg_wdoc *a, const pg_wdoc *b) {
  double ka = a->created > a->edited ? a->created : a->edited, kb = b->created > b->edited ? b->created : b->edited;
  return ka > kb;
}
static long pg_digit_files(const char *dir) {
  DIR *d = opendir(dir);
  struct dirent *e;
  long n = 0;
  while (d && (e = readdir(d)) != NULL) {
    const char *s = e->d_name;
    char full[PATH_MAX * 2 + 8];
    int digits = *s != 0;
    for (; *s; ++s)
      if (*s < '0' || *s > '9')
        digits = 0;
    snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
    if (digits && is_file(full))
      ++n;
  }
  if (d)
    closedir(d);
  return n;
}
static void pg_work_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char scope[32], work_path[PATH_MAX + 16];
  sbuf content, nav;
  const char *sep = pg_icon("sep");
  long counts[3] = {0, 0, 0};
  int si;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_scope", scope, sizeof(scope), "active");
  if (strcmp(scope, "active") && strcmp(scope, "completed") && strcmp(scope, "proposed") && strcmp(scope, "all"))
    snprintf(scope, sizeof(scope), "active");
  if (!c.gname[0] || !c.rname[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested repository was not found.\n", NULL, NULL);
    goto done;
  }
  snprintf(work_path, sizeof(work_path), "%s.work", c.r->path);
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
  sb_adds(&nav, " / work\n");
  for (si = 0; si < 3; ++si) {
    char folder[PATH_MAX * 2];
    DIR *d;
    struct dirent *e;
    snprintf(folder, sizeof(folder), "%s/%s", work_path, work_scopes[si]);
    d = opendir(folder);
    while (d && (e = readdir(d)) != NULL) {
      char dd[PATH_MAX * 2 + 8], rp[PATH_MAX * 2 + 16], *end;
      long id = strtol(e->d_name, &end, 10);
      if (e->d_name[0] < '0' || e->d_name[0] > '9' || *end)
        continue;
      snprintf(dd, sizeof(dd), "%s/%s", folder, e->d_name);
      if (!is_dir(dd) || !doc_allowed(pg_eff(rq), c.g, c.r, work_path, id, P_READ))
        continue;
      snprintf(rp, sizeof(rp), "%s/root", dd);
      if (is_file(rp))
        counts[si]++;
    }
    if (d)
      closedir(d);
  }
  {
    const char *names[4] = {"Active", "Completed", "Proposed", "All"}, *keys[4] = {"active", "completed", "proposed", "all"};
    long totals[4];
    int k;
    totals[0] = counts[0];
    totals[1] = counts[1];
    totals[2] = counts[2];
    totals[3] = counts[0] + counts[1] + counts[2];
    for (k = 0; k < 4; ++k) {
      const char *ul = !strcmp(scope, keys[k]) ? "`_" : "";
      if (k)
        sb_addf(&content, " %s ", sep);
      sb_adds(&content, ul);
      pg_link(&content, 'b', names[k], NULL, "/page/work.mu", "g", c.gname, "r", c.rname, "scope", keys[k], NULL);
      sb_addf(&content, "%s (%ld)", ul, totals[k]);
    }
    sb_adds(&content, "\n\n");
  }
  for (si = 0; si < 3; ++si) {
    char folder[PATH_MAX * 2], cap[16];
    DIR *d;
    struct dirent *e;
    pg_wdoc *docs = NULL;
    size_t nd = 0, i;
    if (strcmp(scope, "all") && strcmp(scope, work_scopes[si]))
      continue;
    snprintf(folder, sizeof(folder), "%s/%s", work_path, work_scopes[si]);
    snprintf(cap, sizeof(cap), "%s", work_scopes[si]);
    cap[0] = (char)(cap[0] - 32);
    d = opendir(folder);
    if (d)
      docs = calloc(512, sizeof(pg_wdoc));
    while (d && docs && (e = readdir(d)) != NULL && nd < 512) {
      char dd[PATH_MAX * 2 + 8], rp[PATH_MAX * 2 + 16], *end;
      long id = strtol(e->d_name, &end, 10);
      doc dc;
      const val *meta, *t;
      if (e->d_name[0] < '0' || e->d_name[0] > '9' || *end)
        continue;
      snprintf(dd, sizeof(dd), "%s/%s", folder, e->d_name);
      if (!is_dir(dd) || !doc_allowed(pg_eff(rq), c.g, c.r, work_path, id, P_READ))
        continue;
      snprintf(rp, sizeof(rp), "%s/root", dd);
      if (!is_file(rp) || !doc_load(rp, &dc))
        continue;
      meta = doc_meta(&dc);
      docs[nd].id = id;
      t = map_get(meta, "title");
      if (!t || t->type == V_NIL)
        snprintf(docs[nd].title, sizeof(docs[nd].title), "Untitled");
      else if (!val_copy(t, docs[nd].title, sizeof(docs[nd].title)))
        docs[nd].title[0] = 0;
      docs[nd].created = meta ? num_of(map_get(meta, "created")) : 0;
      docs[nd].edited = meta ? num_of(map_get(meta, "edited")) : 0;
      if (!meta || !pg_hex_author(meta, docs[nd].author, sizeof(docs[nd].author)))
        snprintf(docs[nd].author, sizeof(docs[nd].author), "unknown");
      docs[nd].comments = pg_digit_files(dd);
      doc_free(&dc);
      ++nd;
    }
    if (d)
      closedir(d);
    {
      size_t a, b;
      for (a = 1; a < nd; ++a) {
        pg_wdoc t2 = docs[a];
        b = a;
        while (b > 0 && pg_wdoc_before(&t2, &docs[b - 1])) {
          docs[b] = docs[b - 1];
          --b;
        }
        docs[b] = t2;
      }
    }
    m_heading(&content, cap, 2);
    if (!nd) {
      sb_addf(&content, "\n`*No %s work documents`*\n\n", work_scopes[si]);
    } else {
      sb_addc(&content, '\n');
      for (i = 0; i < nd; ++i) {
        size_t cut = u8_prefix(docs[i].title, 92);
        char lbl[2300], date_s[32] = "", idbuf[32];
        snprintf(lbl, sizeof(lbl), "%s %.*s%s", pg_icon("file"), (int)cut, docs[i].title, docs[i].title[cut] ? "\xe2\x80\xa6" : "");
        snprintf(idbuf, sizeof(idbuf), "%ld", docs[i].id);
        pg_link(&content, 'b', lbl, NULL, "/page/work_doc.mu", "g", c.gname, "r", c.rname, "id", idbuf, "scope", work_scopes[si], NULL);
        sb_addf(&content, " %s#%ld`f\n", CLR_DIM, docs[i].id);
        if (docs[i].created)
          pg_fmt_localtime(date_s, sizeof(date_s), docs[i].created, "%Y-%m-%d");
        sb_addf(&content, "%s%s by %s`f\n", CLR_DIM, date_s, docs[i].author);
        if (docs[i].comments)
          sb_addf(&content, "%s%ld updates`f\n", CLR_DIM, docs[i].comments);
        sb_addc(&content, '\n');
      }
    }
    free(docs);
  }
  /* the last element, a lone newline, is dropped */
  if (content.n && content.p[content.n - 1] == '\n') {
    content.n--;
    content.p[content.n] = 0;
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "work", rq->st);
done:
  sb_free(&content);
  sb_free(&nav);
}

/* the directory of a document in a scope; for "all" the first existing one */
static void pg_doc_dir(const char *work_path, long id, char *scope, size_t scope_cap, char *out, size_t cap) {
  char a[PATH_MAX * 2], b[PATH_MAX * 2];
  snprintf(a, sizeof(a), "%s/active/%ld", work_path, id);
  snprintf(b, sizeof(b), "%s/completed/%ld", work_path, id);
  if (!strcmp(scope, "all")) {
    if (is_dir(a))
      snprintf(scope, scope_cap, "active");
    else if (is_dir(b))
      snprintf(scope, scope_cap, "completed");
    else
      snprintf(scope, scope_cap, "proposed");
  }
  snprintf(out, cap, "%s/%s/%ld", work_path, scope, id);
}
typedef struct pg_comment {
  long id;
  char *text, author[100], date[32], fmt[16];
} pg_comment;
static void pg_work_doc_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char id_s[64], scope[32], work_path[PATH_MAX + 16], doc_dir[PATH_MAX * 2 + 32], rp[PATH_MAX * 2 + 48], *end;
  long doc_id;
  sbuf content, nav;
  doc dc;
  int have_doc = 0;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_id", id_s, sizeof(id_s), "");
  pg_get(rq, "var_scope", scope, sizeof(scope), "all");
  if (strcmp(scope, "active") && strcmp(scope, "completed") && strcmp(scope, "proposed") && strcmp(scope, "all"))
    snprintf(scope, sizeof(scope), "active");
  if (!c.gname[0] || !c.rname[0] || !id_s[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  {
    char *s = py_strip(id_s);
    doc_id = strtol(s, &end, 10);
    if (end == s || *end || doc_id < 0 || doc_id > 999999999L) {
      pg_error_page(rq, page, "Error", 2, "\nInvalid document ID\n", NULL, NULL);
      goto done;
    }
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested repository was not found\n", NULL, NULL);
    goto done;
  }
  snprintf(work_path, sizeof(work_path), "%s.work", c.r->path);
  if (!doc_allowed(pg_eff(rq), c.g, c.r, work_path, doc_id, P_READ)) {
    pg_error_page(rq, page, "Error", 2, "\nThe requested work document was not found\n", NULL, NULL);
    goto done;
  }
  pg_doc_dir(work_path, doc_id, scope, sizeof(scope), doc_dir, sizeof(doc_dir));
  snprintf(rp, sizeof(rp), "%s/root", doc_dir);
  if (!is_file(rp)) {
    pg_error_page(rq, page, "Not Found", 2, "\nThe requested work document was not found\n", NULL, NULL);
    goto done;
  }
  if (!doc_load(rp, &dc)) {
    pg_error_page(rq, page, "Error", 2, "\nCould not load work document\n", NULL, NULL);
    goto done;
  }
  have_doc = 1;
  {
    sbuf dl;
    char idbuf[32], title[2048], author[100], fmt[32], created_s[48] = "unknown", edited_s[48], sigs[24] = "Document not signed";
    const val *meta = doc_meta(&dc), *cv, *sv, *pv, *tv, *fv;
    double created, edited;
    char *content_text;
    size_t content_n;
    snprintf(idbuf, sizeof(idbuf), "%ld", doc_id);
    sb_init(&dl);
    pg_link(&dl, 'b', "Download", NULL, "/file/workdoc", "g", c.gname, "r", c.rname, "id", idbuf, NULL);
    sb_adds(&nav, ">>\n");
    pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
    sb_adds(&nav, " / ");
    pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
    sb_adds(&nav, " / ");
    pg_link(&nav, 'b', c.rname, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, NULL);
    sb_adds(&nav, " / ");
    pg_link(&nav, 'b', "work", NULL, "/page/work.mu", "g", c.gname, "r", c.rname, NULL);
    sb_addf(&nav, " / #%ld\n\n%s\n", doc_id, sb_str(&dl));
    sb_free(&dl);
    tv = map_get(meta, "title");
    if (!tv || tv->type == V_NIL)
      snprintf(title, sizeof(title), "Untitled");
    else if (!val_copy(tv, title, sizeof(title)))
      title[0] = 0;
    {
      size_t cut = u8_prefix(title, 256);
      int truncated = title[cut] != 0;
      title[cut] = 0;
      if (truncated)
        strncat(title, "\xe2\x80\xa6", sizeof(title) - strlen(title) - 1);
    }
    if (!meta || !pg_hex_author(meta, author, sizeof(author)))
      snprintf(author, sizeof(author), "Unknown");
    fv = map_get(meta, "format");
    if (!fv || !val_copy(fv, fmt, sizeof(fmt)))
      snprintf(fmt, sizeof(fmt), "markdown");
    cv = map_get(&dc.root, "content");
    content_n = cv && val_is_text(cv) ? cv->n : 0;
    content_text = md_dup(cv && val_is_text(cv) ? (const char *)cv->p : "", content_n);
    created = meta ? num_of(map_get(meta, "created")) : 0;
    edited = meta ? num_of(map_get(meta, "edited")) : 0;
    sv = map_get(meta, "signature");
    pv = map_get(meta, "identity");
    if (sv && sv->type == V_BIN && sv->n == 64 && pv && pv->type == V_BIN && pv->n == 64) {
      rnc_identity who;
      snprintf(sigs, sizeof(sigs), "Not valid");
      if (rnc_identity_from_public(&who, pv->p) == RNC_OK &&
          rnc_identity_verify(&who, content_text ? content_text : "", content_n, sv->p) == RNC_OK)
        snprintf(sigs, sizeof(sigs), "Valid");
    }
    m_heading(&content, title, 2);
    sb_addf(&content, "\n%sAuthor    : %s`f\n", CLR_DIM, author);
    sb_addf(&content, "%sSignature : %s`f\n", CLR_DIM, sigs);
    if (created)
      pg_fmt_localtime(created_s, sizeof(created_s), created, "%Y-%m-%d %H:%M");
    sb_addf(&content, "%sCreated   : %s`f\n", CLR_DIM, created_s);
    if (edited && edited != created) {
      pg_fmt_localtime(edited_s, sizeof(edited_s), edited, "%Y-%m-%d %H:%M");
      sb_addf(&content, "%sEdited    : %s`f\n", CLR_DIM, edited_s);
    }
    {
      char cap[32];
      snprintf(cap, sizeof(cap), "%s", scope);
      cap[0] = (char)(cap[0] - 32);
      sb_addf(&content, "%sStatus    : %s`f\n\n", CLR_DIM, cap);
    }
    if (content_text) {
      char *stripped = py_strip(content_text);
      if (*stripped) {
        if (!strcmp(fmt, "micron"))
          sb_adds(&content, stripped);
        else {
          md_conv mc;
          md_init(&mc, PG_MAX_RENDER_WIDTH, NULL);
          md_format_block(&mc, stripped, &content);
        }
        sb_addc(&content, '\n');
      }
    }
    free(content_text);
    {
      DIR *d = opendir(doc_dir);
      struct dirent *e;
      pg_comment *list = calloc(256, sizeof(pg_comment));
      size_t nc = 0, i, k;
      while (d && list && (e = readdir(d)) != NULL && nc < 256) {
        const char *s = e->d_name;
        char full[PATH_MAX * 2 + 64];
        doc cd;
        const val *cm, *cc, *cf;
        int digits = *s != 0;
        for (; *s; ++s)
          if (*s < '0' || *s > '9')
            digits = 0;
        snprintf(full, sizeof(full), "%s/%s", doc_dir, e->d_name);
        if (!digits || !is_file(full) || !doc_load(full, &cd))
          continue;
        cm = doc_meta(&cd);
        cc = map_get(&cd.root, "content");
        cf = map_get(&cd.root, "format");
        list[nc].id = strtol(e->d_name, NULL, 10);
        list[nc].text = md_dup(cc && val_is_text(cc) ? (const char *)cc->p : "", cc && val_is_text(cc) ? cc->n : 0);
        if (!cf || !val_copy(cf, list[nc].fmt, sizeof(list[nc].fmt)))
          snprintf(list[nc].fmt, sizeof(list[nc].fmt), "markdown");
        if (!cm || !pg_hex_author(cm, list[nc].author, sizeof(list[nc].author)))
          snprintf(list[nc].author, sizeof(list[nc].author), "Unknown");
        {
          double cr = cm ? num_of(map_get(cm, "created")) : 0;
          if (cr)
            pg_fmt_localtime(list[nc].date, sizeof(list[nc].date), cr, "%Y-%m-%d %H:%M");
          else
            snprintf(list[nc].date, sizeof(list[nc].date), "unknown");
        }
        doc_free(&cd);
        ++nc;
      }
      if (d)
        closedir(d);
      for (i = 1; i < nc; ++i) {
        pg_comment t = list[i];
        k = i;
        while (k > 0 && list[k - 1].id > t.id) {
          list[k] = list[k - 1];
          --k;
        }
        list[k] = t;
      }
      if (nc) {
        char hd[64];
        snprintf(hd, sizeof(hd), "Updates (%zu)", nc);
        sb_addc(&content, '\n');
        m_heading(&content, hd, 2);
      }
      for (i = 0; i < nc; ++i) {
        sb_addf(&content, "\n%s#%ld by %s on %s`f\n", CLR_DIM, list[i].id, list[i].author, list[i].date);
        if (!strcmp(list[i].fmt, "markdown")) {
          md_conv mc;
          md_init(&mc, PG_MAX_RENDER_WIDTH, NULL);
          md_format_block(&mc, list[i].text ? list[i].text : "", &content);
        } else
          sb_adds(&content, list[i].text ? list[i].text : "");
        sb_addc(&content, '\n');
        free(list[i].text);
      }
      free(list);
    }
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "work_doc", rq->st);
done:
  if (have_doc)
    doc_free(&dc);
  sb_free(&content);
  sb_free(&nav);
}

#endif
