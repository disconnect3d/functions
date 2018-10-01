/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <libioP.h>
#include <stdarg.h>
#include <stdio.h>


/* Write formatted output from FORMAT to a string which is
   allocated with malloc and stored in *STRING_PTR.  */
int
__asprintf_chk (char **result_ptr, int flags, const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vasprintf_chk (result_ptr, flags, format, arg);
  va_end (arg);

  return done;
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@readhat.com>, 20055.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>


size_t
__confstr_chk (int name, char *buf, size_t len, size_t buflen)
{
  if (__glibc_unlikely (buflen < len))
    __chk_fail ();

  return confstr (name, buf, len);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <libioP.h>
#include <stdarg.h>
#include <stdio.h>


/* Write formatted output to D, according to the format string FORMAT.  */
int
__dprintf_chk (int d, int flags, const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vdprintf_chk (d, flags, format, arg);
  va_end (arg);

  return done;
}
/* Generic implementation of __explicit_bzero_chk.
   Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Torbjorn Granlund (tege@sics.se).

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/* This is the generic definition of __explicit_bzero_chk.  The
   __explicit_bzero_chk symbol is used as the implementation of
   explicit_bzero throughout glibc.  If this file is overriden by an
   architecture, both __explicit_bzero_chk and
   __explicit_bzero_chk_internal have to be defined (the latter not as
   an IFUNC).  */

#include <string.h>

void
__explicit_bzero_chk (void *dst, size_t len, size_t dstlen)
{
  /* Inline __memset_chk to avoid a PLT reference to __memset_chk.  */
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();
  memset (dst, '\0', len);
  /* Compiler barrier.  */
  asm volatile ("" ::: "memory");
}

/* libc-internal references use the hidden
   __explicit_bzero_chk_internal symbol.  This is necessary if
   __explicit_bzero_chk is implemented as an IFUNC because some
   targets do not support hidden references to IFUNC symbols.  */
strong_alias (__explicit_bzero_chk, __explicit_bzero_chk_internal)
/* Copyright (C) 2011-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <sys/select.h>


long int
__fdelt_chk (long int d)
{
  if (d < 0 || d >= FD_SETSIZE)
    __chk_fail ();

  return d / __NFDBITS;
}
strong_alias (__fdelt_chk, __fdelt_warn)
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include <stdio.h>
#include <sys/param.h>

char *
__fgets_chk (char *buf, size_t size, int n, FILE *fp)
{
  size_t count;
  char *result;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  _IO_acquire_lock (fp);
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  int old_error = fp->_flags & _IO_ERR_SEEN;
  fp->_flags &= ~_IO_ERR_SEEN;
  count = _IO_getline (fp, buf, MIN ((size_t) n - 1, size), '\n', 1);
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || ((fp->_flags & _IO_ERR_SEEN) && errno != EAGAIN))
    result = NULL;
  else if (count >= size)
    __chk_fail ();
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_flags |= old_error;
  _IO_release_lock (fp);
  return result;
}
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include <stdio.h>
#include <sys/param.h>

char *
__fgets_unlocked_chk (char *buf, size_t size, int n, FILE *fp)
{
  size_t count;
  char *result;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  int old_error = fp->_flags & _IO_ERR_SEEN;
  fp->_flags &= ~_IO_ERR_SEEN;
  count = _IO_getline (fp, buf, MIN ((size_t) n - 1, size), '\n', 1);
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || ((fp->_flags & _IO_ERR_SEEN) && errno != EAGAIN))
    result = NULL;
  else if (count >= size)
    __chk_fail ();
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_flags |= old_error;
  return result;
}
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include "libioP.h"
#include <wchar.h>
#include <sys/param.h>

wchar_t *
__fgetws_chk (wchar_t *buf, size_t size, int n, FILE *fp)
{
  size_t count;
  wchar_t *result;
  int old_error;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  _IO_acquire_lock (fp);
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  old_error = fp->_flags & _IO_ERR_SEEN;
  fp->_flags &= ~_IO_ERR_SEEN;
  count = _IO_getwline (fp, buf, MIN ((size_t) n - 1, size), L'\n', 1);
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || (_IO_ferror_unlocked (fp) && errno != EAGAIN))
    result = NULL;
  else if (count >= size)
    __chk_fail ();
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_flags |= old_error;
  _IO_release_lock (fp);
  return result;
}
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include <wchar.h>
#include <sys/param.h>

wchar_t *
__fgetws_unlocked_chk (wchar_t *buf, size_t size, int n, FILE *fp)
{
  size_t count;
  wchar_t *result;
  int old_error;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  old_error = fp->_flags & _IO_ERR_SEEN;
  fp->_flags &= ~_IO_ERR_SEEN;
  count = _IO_getwline (fp, buf, MIN ((size_t) n - 1, size), L'\n', 1);
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || ((fp->_flags & _IO_ERR_SEEN) && errno != EAGAIN))
    result = NULL;
  else if (count >= size)
    __chk_fail ();
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_flags |= old_error;
  return result;
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include "../libio/libioP.h"


/* Write formatted output to FP from the format string FORMAT.  */
int
___fprintf_chk (FILE *fp, int flag, const char *format, ...)
{
  va_list ap;
  int done;

  _IO_acquire_lock_clear_flags2 (fp);
  if (flag > 0)
    fp->_flags2 |= _IO_FLAGS2_FORTIFY;

  va_start (ap, format);
  done = vfprintf (fp, format, ap);
  va_end (ap);

  if (flag > 0)
    fp->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (fp);

  return done;
}
ldbl_strong_alias (___fprintf_chk, __fprintf_chk)
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include <stdio.h>

size_t
__fread_chk (void *__restrict ptr, size_t ptrlen,
	     size_t size, size_t n, FILE *__restrict stream)
{
  size_t bytes_requested = size * n;
  if (__builtin_expect ((n | size)
			>= (((size_t) 1) << (8 * sizeof (size_t) / 2)), 0))
    {
      if (size != 0 && bytes_requested / size != n)
	__chk_fail ();
    }

  if (__glibc_unlikely (bytes_requested > ptrlen))
    __chk_fail ();

  CHECK_FILE (stream, 0);
  if (bytes_requested == 0)
    return 0;

  size_t bytes_read;
  _IO_acquire_lock (stream);
  bytes_read = _IO_sgetn (stream, (char *) ptr, bytes_requested);
  _IO_release_lock (stream);
  return bytes_requested == bytes_read ? n : bytes_read / size;
}
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include <stdio.h>

size_t
__fread_unlocked_chk (void *__restrict ptr, size_t ptrlen,
		      size_t size, size_t n, FILE *__restrict stream)
{
  size_t bytes_requested = size * n;
  if (__builtin_expect ((n | size)
			>= (((size_t) 1) << (8 * sizeof (size_t) / 2)), 0))
    {
      if (size != 0 && bytes_requested / size != n)
	__chk_fail ();
    }

  if (__glibc_unlikely (bytes_requested > ptrlen))
    __chk_fail ();

  CHECK_FILE (stream, 0);
  if (bytes_requested == 0)
    return 0;

  size_t bytes_read = _IO_sgetn (stream, (char *) ptr, bytes_requested);
  return bytes_requested == bytes_read ? n : bytes_read / size;
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <wchar.h>
#include "../libio/libioP.h"


/* Write formatted output to FP from the format string FORMAT.  */
int
__fwprintf_chk (FILE *fp, int flag, const wchar_t *format, ...)
{
  va_list ap;
  int done;

  _IO_acquire_lock_clear_flags2 (fp);
  if (flag > 0)
    fp->_flags2 |= _IO_FLAGS2_FORTIFY;

  va_start (ap, format);
  done = _IO_vfwprintf (fp, format, ap);
  va_end (ap);

  if (flag > 0)
    fp->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (fp);

  return done;
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <unistd.h>
#include <sys/param.h>


char *
__getcwd_chk (char *buf, size_t size, size_t buflen)
{
  if (size > buflen)
    __chk_fail ();

  return __getcwd (buf, size);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>


int
__getdomainname_chk (char *buf, size_t buflen, size_t nreal)
{
  if (buflen > nreal)
    __chk_fail ();

  return getdomainname (buf, buflen);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <unistd.h>


int
__getgroups_chk (int size, __gid_t list[], size_t listlen)
{
  if (__glibc_unlikely (size < 0))
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (__glibc_unlikely (size * sizeof (__gid_t) > listlen))
    __chk_fail ();

  return __getgroups (size, list);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>


int
__gethostname_chk (char *buf, size_t buflen, size_t nreal)
{
  if (buflen > nreal)
    __chk_fail ();

  return __gethostname (buf, buflen);
}
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "../libio/libioP.h"
#include <limits.h>

char *
__gets_chk (char *buf, size_t size)
{
  size_t count;
  int ch;
  char *retval;

  if (size == 0)
    __chk_fail ();

  _IO_acquire_lock (_IO_stdin);
  ch = _IO_getc_unlocked (_IO_stdin);
  if (ch == EOF)
    {
      retval = NULL;
      goto unlock_return;
    }
  if (ch == '\n')
    count = 0;
  else
    {
      /* This is very tricky since a file descriptor may be in the
	 non-blocking mode. The error flag doesn't mean much in this
	 case. We return an error only when there is a new error. */
      int old_error = _IO_stdin->_flags & _IO_ERR_SEEN;
      _IO_stdin->_flags &= ~_IO_ERR_SEEN;
      buf[0] = (char) ch;
      count = _IO_getline (_IO_stdin, buf + 1, size - 1, '\n', 0) + 1;
      if (_IO_stdin->_flags & _IO_ERR_SEEN)
	{
	  retval = NULL;
	  goto unlock_return;
	}
      else
	_IO_stdin->_flags |= old_error;
    }
  if (count >= size)
    __chk_fail ();
  buf[count] = 0;
  retval = buf;
unlock_return:
  _IO_release_lock (_IO_stdin);
  return retval;
}

link_warning (__gets_chk, "the `gets' function is dangerous and should not be used.")
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <unistd.h>
#include <sys/param.h>


char *
__getwd_chk (char *buf, size_t buflen)
{
  char *res = __getcwd (buf, buflen);
  if (res == NULL && errno == ERANGE)
    __chk_fail ();
  return res;
}

link_warning (getwd,
	      "the `getwd' function is dangerous and should not be used.")
/* Copyright (C) 2009-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <setjmpP.h>

#define __longjmp ____longjmp_chk
#define __libc_siglongjmp __longjmp_chk

#include <setjmp/longjmp.c>
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <locale.h>
#include <wchar.h>


size_t
__mbsnrtowcs_chk (wchar_t *dst, const char **src, size_t nmc, size_t len,
		  mbstate_t *ps, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  return __mbsnrtowcs (dst, src, nmc, len, ps);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <locale.h>
#include <wchar.h>


size_t
__mbsrtowcs_chk (wchar_t *dst, const char **src, size_t len,
		 mbstate_t *ps, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  return __mbsrtowcs (dst, src, len, ps);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <locale.h>
#include <string.h>
#include <wchar.h>


size_t
__mbstowcs_chk (wchar_t *dst, const char *src, size_t len, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  mbstate_t state;

  memset (&state, '\0', sizeof state);
  /* Return how many we wrote (or maybe an error).  */
  return __mbsrtowcs (dst, &src, len, &state);
}
/* Copy memory to memory until the specified number of bytes
   has been copied with error checking.  Overlap is NOT handled correctly.
   Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Torbjorn Granlund (tege@sics.se).

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <string.h>
#include <memcopy.h>

void *
__memcpy_chk (void *dstpp, const void *srcpp, size_t len, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  return memcpy (dstpp, srcpp, len);
}
/* Copy memory to memory until the specified number of bytes
   has been copied with error checking.  Overlap is handled correctly.
   Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Torbjorn Granlund (tege@sics.se).

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <string.h>
#include <memcopy.h>

#ifndef MEMMOVE_CHK
# define MEMMOVE_CHK __memmove_chk
#endif

void *
MEMMOVE_CHK (void *dest, const void *src, size_t len, size_t destlen)
{
  if (__glibc_unlikely (destlen < len))
    __chk_fail ();

  return memmove (dest, src, len);
}
/* Copy memory to memory until the specified number of bytes
   has been copied, return pointer to following byte, with error checking.
   Overlap is NOT handled correctly.
   Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Torbjorn Granlund (tege@sics.se).

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <string.h>
#include <memcopy.h>

void *
__mempcpy_chk (void *dstpp, const void *srcpp, size_t len, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  return __mempcpy (dstpp, srcpp, len);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <string.h>
#include <memcopy.h>

void *
__memset_chk (void *dstpp, int c, size_t len, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  return memset (dstpp, c, len);
}
/* Print output of stream to given obstack.
   Copyright (C) 1996-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */


#include <stdlib.h>
#include <libioP.h>
#include "../libio/strfile.h"
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <obstack.h>
#include <stdarg.h>
#include <stdio_ext.h>


struct _IO_obstack_file
{
  struct _IO_FILE_plus file;
  struct obstack *obstack;
};

extern const struct _IO_jump_t _IO_obstack_jumps libio_vtable attribute_hidden;

int
__obstack_vprintf_chk (struct obstack *obstack, int flags, const char *format,
		       va_list args)
{
  struct obstack_FILE
    {
      struct _IO_obstack_file ofile;
    } new_f;
  int result;
  int size;
  int room;

#ifdef _IO_MTSAFE_IO
  new_f.ofile.file.file._lock = NULL;
#endif

  _IO_no_init (&new_f.ofile.file.file, _IO_USER_LOCK, -1, NULL, NULL);
  _IO_JUMPS (&new_f.ofile.file) = &_IO_obstack_jumps;
  room = obstack_room (obstack);
  size = obstack_object_size (obstack) + room;
  if (size == 0)
    {
      /* We have to handle the allocation a bit different since the
	 `_IO_str_init_static' function would handle a size of zero
	 different from what we expect.  */

      /* Get more memory.  */
      obstack_make_room (obstack, 64);

      /* Recompute how much room we have.  */
      room = obstack_room (obstack);
      size = room;

      assert (size != 0);
    }

  _IO_str_init_static_internal ((struct _IO_strfile_ *) &new_f.ofile,
				obstack_base (obstack),
				size, obstack_next_free (obstack));
  /* Now allocate the rest of the current chunk.  */
  assert (size == (new_f.ofile.file.file._IO_write_end
		   - new_f.ofile.file.file._IO_write_base));
  assert (new_f.ofile.file.file._IO_write_ptr
	  == (new_f.ofile.file.file._IO_write_base
	      + obstack_object_size (obstack)));
  obstack_blank_fast (obstack, room);

  new_f.ofile.obstack = obstack;

  /* For flags > 0 (i.e. __USE_FORTIFY_LEVEL > 1) request that %n
     can only come from read-only format strings.  */
  if (flags > 0)
    new_f.ofile.file.file._flags2 |= _IO_FLAGS2_FORTIFY;

  result = _IO_vfprintf (&new_f.ofile.file.file, format, args);

  /* Shrink the buffer to the space we really currently need.  */
  obstack_blank_fast (obstack, (new_f.ofile.file.file._IO_write_ptr
				- new_f.ofile.file.file._IO_write_end));

  return result;
}
libc_hidden_def (__obstack_vprintf_chk)


int
__obstack_printf_chk (struct obstack *obstack, int flags, const char *format,
		      ...)
{
  int result;
  va_list ap;
  va_start (ap, format);
  result = __obstack_vprintf_chk (obstack, flags, format, ap);
  va_end (ap);
  return result;
}
/* Copyright (C) 2012-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <sys/poll.h>


int
__poll_chk (struct pollfd *fds, nfds_t nfds, int timeout, __SIZE_TYPE__ fdslen)
{
  if (fdslen / sizeof (*fds) < nfds)
    __chk_fail ();

  return __poll (fds, nfds, timeout);
}
/* Copyright (C) 2012-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <sys/poll.h>


int
__ppoll_chk (struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
	     const __sigset_t *ss, __SIZE_TYPE__ fdslen)
{
  if (fdslen / sizeof (*fds) < nfds)
    __chk_fail ();

  return ppoll (fds, nfds, timeout, ss);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>
#include <sys/param.h>


ssize_t
__pread64_chk (int fd, void *buf, size_t nbytes, off64_t offset, size_t buflen)
{
  if (nbytes > buflen)
    __chk_fail ();

  return __libc_pread64 (fd, buf, nbytes, offset);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>
#include <sys/param.h>


ssize_t
__pread_chk (int fd, void *buf, size_t nbytes, off_t offset, size_t buflen)
{
  if (nbytes > buflen)
    __chk_fail ();

  return __pread (fd, buf, nbytes, offset);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include "../libio/libioP.h"


/* Write formatted output to stdout from the format string FORMAT.  */
int
___printf_chk (int flag, const char *format, ...)
{
  va_list ap;
  int done;

  _IO_acquire_lock_clear_flags2 (stdout);
  if (flag > 0)
    stdout->_flags2 |= _IO_FLAGS2_FORTIFY;

  va_start (ap, format);
  done = vfprintf (stdout, format, ap);
  va_end (ap);

  if (flag > 0)
    stdout->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (stdout);

  return done;
}
ldbl_strong_alias (___printf_chk, __printf_chk)
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>
#include <sys/param.h>
#ifdef HAVE_INLINED_SYSCALLS
# include <errno.h>
# include <sysdep.h>
#endif


ssize_t
__read_chk (int fd, void *buf, size_t nbytes, size_t buflen)
{
  if (nbytes > buflen)
    __chk_fail ();

#ifdef HAVE_INLINED_SYSCALLS
  return INLINE_SYSCALL (read, 3, fd, buf, nbytes);
#else
  return __read (fd, buf, nbytes);
#endif
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>
#include <sys/param.h>
#ifdef HAVE_INLINED_SYSCALLS
# include <errno.h>
# include <sysdep.h>
#endif


ssize_t
__readlink_chk (const char *path, void *buf, size_t len, size_t buflen)
{
  if (len > buflen)
    __chk_fail ();

  return __readlink (path, buf, len);
}
/* Copyright (C) 2006-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>
#include <sys/param.h>


ssize_t
__readlinkat_chk (int fd, const char *path, void *buf, size_t len,
		  size_t buflen)
{
  if (len > buflen)
    __chk_fail ();

  return readlinkat (fd, path, buf, len);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


char *
__realpath_chk (const char *buf, char *resolved, size_t resolvedlen)
{
#ifdef PATH_MAX
  if (resolvedlen < PATH_MAX)
    __chk_fail ();

  return __realpath (buf, resolved);
#else
  long int pathmax =__pathconf (buf, _PC_PATH_MAX);
  if (pathmax != -1)
    {
      /* We do have a fixed limit.  */
      if (resolvedlen < pathmax)
	__chk_fail ();

      return __realpath (buf, resolved);
    }

  /* Since there is no fixed limit we check whether the size is large
     enough.  */
  char *res = __realpath (buf, NULL);
  if (res != NULL)
    {
      size_t actlen = strlen (res) + 1;
      if (actlen > resolvedlen)
	__chk_fail ();

      memcpy (resolved, res, actlen);
      free (res);
      res = resolved;
    }

  return res;
#endif
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <sys/param.h>
#include <sys/socket.h>


ssize_t
__recv_chk (int fd, void *buf, size_t n, size_t buflen, int flags)
{
  if (n > buflen)
    __chk_fail ();

  return __recv (fd, buf, n, flags);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <sys/param.h>
#include <sys/socket.h>


ssize_t
__recvfrom_chk (int fd, void *buf, size_t n, size_t buflen, int flags,
		__SOCKADDR_ARG addr, socklen_t *addr_len)
{
  if (n > buflen)
    __chk_fail ();

  return __recvfrom (fd, buf, n, flags, addr, addr_len);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <libioP.h>
#include <stdarg.h>
#include <stdio.h>


/* Write formatted output into S, according to the format
   string FORMAT, writing no more than MAXLEN characters.  */
/* VARARGS5 */
int
___snprintf_chk (char *s, size_t maxlen, int flags, size_t slen,
		 const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vsnprintf_chk (s, maxlen, flags, slen, format, arg);
  va_end (arg);

  return done;
}
ldbl_strong_alias (___snprintf_chk, __snprintf_chk)
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <libioP.h>
#include <stdarg.h>
#include <stdio.h>

/* Write formatted output into S, according to the format string FORMAT.  */
/* VARARGS4 */
int
___sprintf_chk (char *s, int flags, size_t slen, const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vsprintf_chk (s, flags, slen, format, arg);
  va_end (arg);

  return done;
}
ldbl_strong_alias (___sprintf_chk, __sprintf_chk)
/* Copyright (C) 1992-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>


/* Copy SRC to DEST, returning the address of the terminating '\0' in DEST.  */
char *
__stpcpy_chk (char *dest, const char *src, size_t destlen)
{
  size_t len = strlen (src);
  if (len >= destlen)
    __chk_fail ();

  return memcpy (dest, src, len + 1) + len;
}
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/* This is almost copied from strncpy.c, written by Torbjorn Granlund.  */

#include <string.h>


/* Copy no more than N characters of SRC to DEST, returning the address of
   the terminating '\0' in DEST, if any, or else DEST + N.  */
char *
__stpncpy_chk (char *dest, const char *src, size_t n, size_t destlen)
{
  if (__builtin_expect (destlen < n, 0))
    __chk_fail ();

  return __stpncpy (dest, src, n);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <string.h>
#include <memcopy.h>


/* Append SRC on the end of DEST.  */
char *
__strcat_chk (char *dest, const char *src, size_t destlen)
{
  char *s1 = dest;
  const char *s2 = src;
  char c;

  /* Find the end of the string.  */
  do
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      c = *s1++;
    }
  while (c != '\0');

  /* Make S1 point before the next character, so we can increment
     it while memory is read (wins on pipelined cpus).  */
  ++destlen;
  s1 -= 2;

  do
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      c = *s2++;
      *++s1 = c;
    }
  while (c != '\0');

  return dest;
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stddef.h>
#include <string.h>
#include <memcopy.h>

#undef strcpy

/* Copy SRC to DEST with checking of destination buffer overflow.  */
char *
__strcpy_chk (char *dest, const char *src, size_t destlen)
{
  size_t len = strlen (src);
  if (len >= destlen)
    __chk_fail ();

  return memcpy (dest, src, len + 1);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <string.h>

#include <memcopy.h>


char *
__strncat_chk (char *s1, const char *s2, size_t n, size_t s1len)
{
  char c;
  char *s = s1;

  /* Find the end of S1.  */
  do
    {
      if (__glibc_unlikely (s1len-- == 0))
	__chk_fail ();
      c = *s1++;
    }
  while (c != '\0');

  /* Make S1 point before next character, so we can increment
     it while memory is read (wins on pipelined cpus).  */
  ++s1len;
  s1 -= 2;

  if (n >= 4)
    {
      size_t n4 = n >> 2;
      do
	{
	  if (__glibc_unlikely (s1len-- == 0))
	    __chk_fail ();
	  c = *s2++;
	  *++s1 = c;
	  if (c == '\0')
	    return s;
	  if (__glibc_unlikely (s1len-- == 0))
	    __chk_fail ();
	  c = *s2++;
	  *++s1 = c;
	  if (c == '\0')
	    return s;
	  if (__glibc_unlikely (s1len-- == 0))
	    __chk_fail ();
	  c = *s2++;
	  *++s1 = c;
	  if (c == '\0')
	    return s;
	  if (__glibc_unlikely (s1len-- == 0))
	    __chk_fail ();
	  c = *s2++;
	  *++s1 = c;
	  if (c == '\0')
	    return s;
	} while (--n4 > 0);
      n &= 3;
    }

  while (n > 0)
    {
      if (__glibc_unlikely (s1len-- == 0))
	__chk_fail ();
      c = *s2++;
      *++s1 = c;
      if (c == '\0')
	return s;
      n--;
    }

  if (c != '\0')
    {
      if (__glibc_unlikely (s1len-- == 0))
	__chk_fail ();
      *++s1 = '\0';
    }

  return s;
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <string.h>
#include <memcopy.h>


char *
__strncpy_chk (char *s1, const char *s2, size_t n, size_t s1len)
{
  if (__builtin_expect (s1len < n, 0))
    __chk_fail ();

  return strncpy (s1, s2, n);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <wchar.h>

/* Write formatted output into S, according to the format string FORMAT.  */
/* VARARGS5 */
int
__swprintf_chk (wchar_t *s, size_t n, int flag, size_t s_len,
		const wchar_t *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vswprintf_chk (s, n, flag, s_len, format, arg);
  va_end (arg);

  return done;
}
/* Test and measure stpcpy checking functions.
   Copyright (C) 1999-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Written by Jakub Jelinek <jakub@redhat.com>, 1999.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#define STRCPY_RESULT(dst, len) ((dst) + (len))
#define TEST_MAIN
#define TEST_NAME "stpcpy_chk"
#include "../string/test-string.h"

extern void __attribute__ ((noreturn)) __chk_fail (void);
char *simple_stpcpy_chk (char *, const char *, size_t);
extern char *normal_stpcpy (char *, const char *, size_t)
  __asm ("stpcpy");
extern char *__stpcpy_chk (char *, const char *, size_t);

IMPL (simple_stpcpy_chk, 0)
IMPL (normal_stpcpy, 1)
IMPL (__stpcpy_chk, 2)

char *
simple_stpcpy_chk (char *dst, const char *src, size_t len)
{
  if (! len)
    __chk_fail ();
  while ((*dst++ = *src++) != '\0')
    if (--len == 0)
      __chk_fail ();
  return dst - 1;
}

#include "test-strcpy_chk.c"
/* Test and measure __strcpy_chk functions.
   Copyright (C) 1999-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Written by Jakub Jelinek <jakub@redhat.com>, 1999.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef STRCPY_RESULT
# define STRCPY_RESULT(dst, len) dst
# define TEST_MAIN
# define TEST_NAME "strcpy_chk"
# include "../string/test-string.h"

/* This test case implicitly tests the availability of the __chk_fail
   symbol, which is part of the public ABI and may be used
   externally. */
extern void __attribute__ ((noreturn)) __chk_fail (void);
char *simple_strcpy_chk (char *, const char *, size_t);
extern char *normal_strcpy (char *, const char *, size_t)
  __asm ("strcpy");
extern char *__strcpy_chk (char *, const char *, size_t);

IMPL (simple_strcpy_chk, 0)
IMPL (normal_strcpy, 1)
IMPL (__strcpy_chk, 2)

char *
simple_strcpy_chk (char *dst, const char *src, size_t len)
{
  char *ret = dst;
  if (! len)
    __chk_fail ();
  while ((*dst++ = *src++) != '\0')
    if (--len == 0)
      __chk_fail ();
  return ret;
}
#endif

#include <fcntl.h>
#include <paths.h>
#include <setjmp.h>
#include <signal.h>

static int test_main (void);
#define TEST_FUNCTION test_main
#include <support/test-driver.c>
#include <support/support.h>

volatile int chk_fail_ok;
jmp_buf chk_fail_buf;

static void
handler (int sig)
{
  if (chk_fail_ok)
    {
      chk_fail_ok = 0;
      longjmp (chk_fail_buf, 1);
    }
  else
    _exit (127);
}

typedef char *(*proto_t) (char *, const char *, size_t);

static void
do_one_test (impl_t *impl, char *dst, const char *src,
	     size_t len, size_t dlen)
{
  char *res;
  if (dlen <= len)
    {
      if (impl->test == 1)
	return;

      chk_fail_ok = 1;
      if (setjmp (chk_fail_buf) == 0)
	{
	  res = CALL (impl, dst, src, dlen);
	  printf ("*** Function %s (%zd; %zd) did not __chk_fail\n",
		  impl->name, len, dlen);
	  chk_fail_ok = 0;
	  ret = 1;
	}
      return;
    }
  else
    res = CALL (impl, dst, src, dlen);

  if (res != STRCPY_RESULT (dst, len))
    {
      printf ("Wrong result in function %s %p %p\n", impl->name,
	      res, STRCPY_RESULT (dst, len));
      ret = 1;
      return;
    }

  if (strcmp (dst, src) != 0)
    {
      printf ("Wrong result in function %s dst \"%s\" src \"%s\"\n",
	      impl->name, dst, src);
      ret = 1;
      return;
    }
}

static void
do_test (size_t align1, size_t align2, size_t len, size_t dlen, int max_char)
{
  size_t i;
  char *s1, *s2;

  align1 &= 7;
  if (align1 + len >= page_size)
    return;

  align2 &= 7;
  if (align2 + len >= page_size)
    return;

  s1 = (char *) buf1 + align1;
  s2 = (char *) buf2 + align2;

  for (i = 0; i < len; i++)
    s1[i] = 32 + 23 * i % (max_char - 32);
  s1[len] = 0;

  FOR_EACH_IMPL (impl, 0)
    do_one_test (impl, s2, s1, len, dlen);
}

static void
do_random_tests (void)
{
  size_t i, j, n, align1, align2, len, dlen;
  unsigned char *p1 = buf1 + page_size - 512;
  unsigned char *p2 = buf2 + page_size - 512;
  unsigned char *res;

  for (n = 0; n < ITERATIONS; n++)
    {
      align1 = random () & 31;
      if (random () & 1)
	align2 = random () & 31;
      else
	align2 = align1 + (random () & 24);
      len = random () & 511;
      j = align1;
      if (align2 > j)
	j = align2;
      if (len + j >= 511)
	len = 510 - j - (random () & 7);
      j = len + align1 + 64;
      if (j > 512)
	j = 512;
      for (i = 0; i < j; i++)
	{
	  if (i == len + align1)
	    p1[i] = 0;
	  else
	    {
	      p1[i] = random () & 255;
	      if (i >= align1 && i < len + align1 && !p1[i])
		p1[i] = (random () & 127) + 3;
	    }
	}

      switch (random () & 7)
	{
	case 0:
	  dlen = len - (random () & 31);
	  if (dlen > len)
	    dlen = len;
	  break;
	case 1:
	  dlen = (size_t) -1;
	  break;
	case 2:
	  dlen = len + 1 + (random () & 65535);
	  break;
	case 3:
	  dlen = len + 1 + (random () & 255);
	  break;
	case 4:
	  dlen = len + 1 + (random () & 31);
	  break;
	case 5:
	  dlen = len + 1 + (random () & 7);
	  break;
	case 6:
	  dlen = len + 1 + (random () & 3);
	  break;
	default:
	  dlen = len + 1;
	  break;
	}

      FOR_EACH_IMPL (impl, 1)
	{
	  if (dlen <= len)
	    {
	      if (impl->test != 1)
		{
		  chk_fail_ok = 1;
		  if (setjmp (chk_fail_buf) == 0)
		    {
		      res = (unsigned char *)
			    CALL (impl, (char *) p2 + align2,
				  (char *) p1 + align1, dlen);
		      printf ("Iteration %zd - did not __chk_fail\n", n);
		      chk_fail_ok = 0;
		      ret = 1;
		    }
		}
	      continue;
	    }
	  memset (p2 - 64, '\1', 512 + 64);
	  res = (unsigned char *)
		CALL (impl, (char *) p2 + align2, (char *) p1 + align1, dlen);
	  if (res != STRCPY_RESULT (p2 + align2, len))
	    {
	      printf ("\
Iteration %zd - wrong result in function %s (%zd, %zd, %zd) %p != %p\n",
		      n, impl->name, align1, align2, len, res,
		      STRCPY_RESULT (p2 + align2, len));
	      ret = 1;
	    }
	  for (j = 0; j < align2 + 64; ++j)
	    {
	      if (p2[j - 64] != '\1')
		{
		  printf ("\
Iteration %zd - garbage before, %s (%zd, %zd, %zd)\n",
			  n, impl->name, align1, align2, len);
		  ret = 1;
		  break;
		}
	    }
	  for (j = align2 + len + 1; j < 512; ++j)
	    {
	      if (p2[j] != '\1')
		{
		  printf ("\
Iteration %zd - garbage after, %s (%zd, %zd, %zd)\n",
			  n, impl->name, align1, align2, len);
		  ret = 1;
		  break;
		}
	    }
	  if (memcmp (p1 + align1, p2 + align2, len + 1))
	    {
	      printf ("\
Iteration %zd - different strings, %s (%zd, %zd, %zd)\n",
		      n, impl->name, align1, align2, len);
	      ret = 1;
	    }
	}
    }
}

static int
test_main (void)
{
  size_t i;

  set_fortify_handler (handler);

  test_init ();

  printf ("%23s", "");
  FOR_EACH_IMPL (impl, 0)
    printf ("\t%s", impl->name);
  putchar ('\n');

  for (i = 0; i < 16; ++i)
    {
      do_test (0, 0, i, i + 1, 127);
      do_test (0, 0, i, i + 1, 255);
      do_test (0, i, i, i + 1, 127);
      do_test (i, 0, i, i + 1, 255);
    }

  for (i = 1; i < 8; ++i)
    {
      do_test (0, 0, 8 << i, (8 << i) + 1, 127);
      do_test (8 - i, 2 * i, (8 << i), (8 << i) + 1, 127);
    }

  for (i = 1; i < 8; ++i)
    {
      do_test (i, 2 * i, (8 << i), (8 << i) + 1, 127);
      do_test (2 * i, i, (8 << i), (8 << i) + 1, 255);
      do_test (i, i, (8 << i), (8 << i) + 1, 127);
      do_test (i, i, (8 << i), (8 << i) + 1, 255);
    }

  for (i = 0; i < 16; ++i)
    {
      do_test (0, 0, i, i + 256, 127);
      do_test (0, 0, i, i + 256, 255);
      do_test (0, i, i, i + 256, 127);
      do_test (i, 0, i, i + 256, 255);
    }

  for (i = 1; i < 8; ++i)
    {
      do_test (0, 0, 8 << i, (8 << i) + 256, 127);
      do_test (8 - i, 2 * i, (8 << i), (8 << i) + 256, 127);
    }

  for (i = 1; i < 8; ++i)
    {
      do_test (i, 2 * i, (8 << i), (8 << i) + 256, 127);
      do_test (2 * i, i, (8 << i), (8 << i) + 256, 255);
      do_test (i, i, (8 << i), (8 << i) + 256, 127);
      do_test (i, i, (8 << i), (8 << i) + 256, 255);
    }

  for (i = 0; i < 16; ++i)
    {
      do_test (0, 0, i, i, 127);
      do_test (0, 0, i, i + 2, 255);
      do_test (0, i, i, i + 3, 127);
      do_test (i, 0, i, i + 4, 255);
    }

  for (i = 1; i < 8; ++i)
    {
      do_test (0, 0, 8 << i, (8 << i) - 15, 127);
      do_test (8 - i, 2 * i, (8 << i), (8 << i) + 5, 127);
    }

  for (i = 1; i < 8; ++i)
    {
      do_test (i, 2 * i, (8 << i), (8 << i) + i, 127);
      do_test (2 * i, i, (8 << i), (8 << i) + (i - 1), 255);
      do_test (i, i, (8 << i), (8 << i) + i + 2, 127);
      do_test (i, i, (8 << i), (8 << i) + i + 3, 255);
    }

  do_random_tests ();
  return ret;
}
/* Basic test to make sure doing a longjmp to a jmpbuf with an invalid sp
   is caught by the fortification code.  */
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


static int do_test(void);
#define TEST_FUNCTION do_test ()
#include "../test-skeleton.c"


static jmp_buf b;


static void
__attribute__ ((noinline))
f (void)
{
  char buf[1000];
  asm volatile ("" : "=m" (buf));

  if (setjmp (b) != 0)
    {
      puts ("second longjmp succeeded");
      exit (1);
    }
}


static bool expected_to_fail;


static void
handler (int sig)
{
  if (expected_to_fail)
    _exit (0);
  else
    {
      static const char msg[] = "unexpected longjmp failure\n";
      TEMP_FAILURE_RETRY (write (STDOUT_FILENO, msg, sizeof (msg) - 1));
      _exit (1);
    }
}


static int
do_test (void)
{
  set_fortify_handler (handler);


  expected_to_fail = false;

  if (setjmp (b) == 0)
    {
      longjmp (b, 1);
      /* NOTREACHED */
      printf ("first longjmp returned\n");
      return 1;
    }


  expected_to_fail = true;

  f ();
  longjmp (b, 1);

  puts ("second longjmp returned");
  return 1;
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <unistd.h>


int
__ttyname_r_chk (int fd, char *buf, size_t buflen, size_t nreal)
{
  if (buflen > nreal)
    __chk_fail ();

  return __ttyname_r (fd, buf, buflen);
}
/* Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include "../libio/libioP.h"
#include "../libio/strfile.h"

int
__vasprintf_chk (char **result_ptr, int flags, const char *format,
		 va_list args)
{
  /* Initial size of the buffer to be used.  Will be doubled each time an
     overflow occurs.  */
  const size_t init_string_size = 100;
  char *string;
  _IO_strfile sf;
  int ret;
  size_t needed;
  size_t allocated;
  /* No need to clear the memory here (unlike for open_memstream) since
     we know we will never seek on the stream.  */
  string = (char *) malloc (init_string_size);
  if (string == NULL)
    return -1;
#ifdef _IO_MTSAFE_IO
  sf._sbf._f._lock = NULL;
#endif
  _IO_no_init (&sf._sbf._f, _IO_USER_LOCK, -1, NULL, NULL);
  _IO_JUMPS (&sf._sbf) = &_IO_str_jumps;
  _IO_str_init_static_internal (&sf, string, init_string_size, string);
  sf._sbf._f._flags &= ~_IO_USER_BUF;
  sf._s._allocate_buffer_unused = (_IO_alloc_type) malloc;
  sf._s._free_buffer_unused = (_IO_free_type) free;

  /* For flags > 0 (i.e. __USE_FORTIFY_LEVEL > 1) request that %n
     can only come from read-only format strings.  */
  if (flags > 0)
    sf._sbf._f._flags2 |= _IO_FLAGS2_FORTIFY;

  ret = _IO_vfprintf (&sf._sbf._f, format, args);
  if (ret < 0)
    {
      free (sf._sbf._f._IO_buf_base);
      return ret;
    }
  /* Only use realloc if the size we need is of the same (binary)
     order of magnitude then the memory we allocated.  */
  needed = sf._sbf._f._IO_write_ptr - sf._sbf._f._IO_write_base + 1;
  allocated = sf._sbf._f._IO_write_end - sf._sbf._f._IO_write_base;
  if ((allocated >> 1) <= needed)
    *result_ptr = (char *) realloc (sf._sbf._f._IO_buf_base, needed);
  else
    {
      *result_ptr = (char *) malloc (needed);
      if (*result_ptr != NULL)
	{
	  memcpy (*result_ptr, sf._sbf._f._IO_buf_base, needed - 1);
	  free (sf._sbf._f._IO_buf_base);
	}
      else
	/* We have no choice, use the buffer we already have.  */
	*result_ptr = (char *) realloc (sf._sbf._f._IO_buf_base, needed);
    }
  if (*result_ptr == NULL)
    *result_ptr = sf._sbf._f._IO_buf_base;
  (*result_ptr)[needed - 1] = '\0';
  return ret;
}
libc_hidden_def (__vasprintf_chk)
/* Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include <libioP.h>
#include <stdio_ext.h>

int
__vdprintf_chk (int d, int flags, const char *format, va_list arg)
{
  struct _IO_FILE_plus tmpfil;
  struct _IO_wide_data wd;
  int done;

#ifdef _IO_MTSAFE_IO
  tmpfil.file._lock = NULL;
#endif
  _IO_no_init (&tmpfil.file, _IO_USER_LOCK, 0, &wd, &_IO_wfile_jumps);
  _IO_JUMPS (&tmpfil) = &_IO_file_jumps;
  _IO_new_file_init_internal (&tmpfil);
  if (_IO_file_attach (&tmpfil.file, d) == NULL)
    {
      _IO_un_link (&tmpfil);
      return EOF;
    }
  tmpfil.file._flags |= _IO_DELETE_DONT_CLOSE;

  _IO_mask_flags (&tmpfil.file, _IO_NO_READS,
		  _IO_NO_READS+_IO_NO_WRITES+_IO_IS_APPENDING);

  /* For flags > 0 (i.e. __USE_FORTIFY_LEVEL > 1) request that %n
     can only come from read-only format strings.  */
  if (flags > 0)
    tmpfil.file._flags2 |= _IO_FLAGS2_FORTIFY;

  done = _IO_vfprintf (&tmpfil.file, format, arg);

  _IO_FINISH (&tmpfil.file);

  return done;
}
libc_hidden_def (__vdprintf_chk)
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include "../libio/libioP.h"


/* Write formatted output to FP from the format string FORMAT.  */
int
___vfprintf_chk (FILE *fp, int flag, const char *format, va_list ap)
{
  int done;

  _IO_acquire_lock_clear_flags2 (fp);
  if (flag > 0)
    fp->_flags2 |= _IO_FLAGS2_FORTIFY;

  done = vfprintf (fp, format, ap);

  if (flag > 0)
    fp->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (fp);

  return done;
}
ldbl_hidden_def (___vfprintf_chk, __vfprintf_chk)
ldbl_strong_alias (___vfprintf_chk, __vfprintf_chk)
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <wchar.h>
#include "../libio/libioP.h"


/* Write formatted output to FP from the format string FORMAT.  */
int
__vfwprintf_chk (FILE *fp, int flag, const wchar_t *format, va_list ap)
{
  int done;

  _IO_acquire_lock_clear_flags2 (fp);
  if (flag > 0)
    fp->_flags2 |= _IO_FLAGS2_FORTIFY;

  done = _IO_vfwprintf (fp, format, ap);

  if (flag > 0)
    fp->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (fp);

  return done;
}
libc_hidden_def (__vfwprintf_chk)
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include "../libio/libioP.h"


/* Write formatted output to stdout from the format string FORMAT.  */
int
___vprintf_chk (int flag, const char *format, va_list ap)
{
  int done;

  _IO_acquire_lock_clear_flags2 (stdout);
  if (flag > 0)
    stdout->_flags2 |= _IO_FLAGS2_FORTIFY;

  done = vfprintf (stdout, format, ap);

  if (flag > 0)
    stdout->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (stdout);

  return done;
}
ldbl_strong_alias (___vprintf_chk, __vprintf_chk)
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include "../libio/libioP.h"
#include "../libio/strfile.h"

extern const struct _IO_jump_t _IO_strn_jumps libio_vtable attribute_hidden;

/* Write formatted output into S, according to the format
   string FORMAT, writing no more than MAXLEN characters.  */
/* VARARGS5 */
int
___vsnprintf_chk (char *s, size_t maxlen, int flags, size_t slen,
		  const char *format, va_list args)
{
  /* XXX Maybe for less strict version do not fail immediately.
     Though, maxlen is supposed to be the size of buffer pointed
     to by s, so a conforming program can't pass such maxlen
     to *snprintf.  */
  if (__glibc_unlikely (slen < maxlen))
    __chk_fail ();

  _IO_strnfile sf;
  int ret;
#ifdef _IO_MTSAFE_IO
  sf.f._sbf._f._lock = NULL;
#endif

  /* We need to handle the special case where MAXLEN is 0.  Use the
     overflow buffer right from the start.  */
  if (maxlen == 0)
    {
      s = sf.overflow_buf;
      maxlen = sizeof (sf.overflow_buf);
    }

  _IO_no_init (&sf.f._sbf._f, _IO_USER_LOCK, -1, NULL, NULL);
  _IO_JUMPS (&sf.f._sbf) = &_IO_strn_jumps;
  s[0] = '\0';

  /* For flags > 0 (i.e. __USE_FORTIFY_LEVEL > 1) request that %n
     can only come from read-only format strings.  */
  if (flags > 0)
    sf.f._sbf._f._flags2 |= _IO_FLAGS2_FORTIFY;

  _IO_str_init_static_internal (&sf.f, s, maxlen - 1, s);
  ret = _IO_vfprintf (&sf.f._sbf._f, format, args);

  if (sf.f._sbf._f._IO_buf_base != sf.overflow_buf)
    *sf.f._sbf._f._IO_write_ptr = '\0';
  return ret;
}
ldbl_hidden_def (___vsnprintf_chk, __vsnprintf_chk)
ldbl_strong_alias (___vsnprintf_chk, __vsnprintf_chk)
/* Copyright (C) 1994-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include "../libio/libioP.h"
#include "../libio/strfile.h"


static int _IO_str_chk_overflow (FILE *fp, int c) __THROW;

static int
_IO_str_chk_overflow (FILE *fp, int c)
{
  /* When we come to here this means the user supplied buffer is
     filled.  */
  __chk_fail ();
}


static const struct _IO_jump_t _IO_str_chk_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_chk_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};


int
___vsprintf_chk (char *s, int flags, size_t slen, const char *format,
		 va_list args)
{
  _IO_strfile f;
  int ret;
#ifdef _IO_MTSAFE_IO
  f._sbf._f._lock = NULL;
#endif

  if (slen == 0)
    __chk_fail ();

  _IO_no_init (&f._sbf._f, _IO_USER_LOCK, -1, NULL, NULL);
  _IO_JUMPS (&f._sbf) = &_IO_str_chk_jumps;
  s[0] = '\0';
  _IO_str_init_static_internal (&f, s, slen - 1, s);

  /* For flags > 0 (i.e. __USE_FORTIFY_LEVEL > 1) request that %n
     can only come from read-only format strings.  */
  if (flags > 0)
    f._sbf._f._flags2 |= _IO_FLAGS2_FORTIFY;

  ret = _IO_vfprintf (&f._sbf._f, format, args);

  *f._sbf._f._IO_write_ptr = '\0';
  return ret;
}
ldbl_hidden_def (___vsprintf_chk, __vsprintf_chk)
ldbl_strong_alias (___vsprintf_chk, __vsprintf_chk)
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <wchar.h>
#include "../libio/libioP.h"
#include "../libio/strfile.h"


/* Write formatted output into S, according to the format
   string FORMAT, writing no more than MAXLEN characters.  */
/* VARARGS5 */
int
__vswprintf_chk (wchar_t *s, size_t maxlen, int flags, size_t slen,
		 const wchar_t *format, va_list args)
{
  /* XXX Maybe for less strict version do not fail immediately.
     Though, maxlen is supposed to be the size of buffer pointed
     to by s, so a conforming program can't pass such maxlen
     to *snprintf.  */
  if (__glibc_unlikely (slen < maxlen))
    __chk_fail ();

  _IO_wstrnfile sf;
  struct _IO_wide_data wd;
  int ret;
#ifdef _IO_MTSAFE_IO
  sf.f._sbf._f._lock = NULL;
#endif

  /* We need to handle the special case where MAXLEN is 0.  Use the
     overflow buffer right from the start.  */
  if (__glibc_unlikely (maxlen == 0))
    /* Since we have to write at least the terminating L'\0' a buffer
       length of zero always makes the function fail.  */
    return -1;

  _IO_no_init (&sf.f._sbf._f, _IO_USER_LOCK, 0, &wd, &_IO_wstrn_jumps);
  _IO_fwide (&sf.f._sbf._f, 1);
  s[0] = L'\0';

  /* For flags > 0 (i.e. __USE_FORTIFY_LEVEL > 1) request that %n
     can only come from read-only format strings.  */
  if (flags > 0)
    sf.f._sbf._f._flags2 |= _IO_FLAGS2_FORTIFY;

  _IO_wstr_init_static (&sf.f._sbf._f, s, maxlen - 1, s);
  ret = _IO_vfwprintf ((FILE *) &sf.f._sbf, format, args);

  if (sf.f._sbf._f._wide_data->_IO_buf_base == sf.overflow_buf)
    /* ISO C99 requires swprintf/vswprintf to return an error if the
       output does not fit int he provided buffer.  */
    return -1;

  /* Terminate the string.  */
  *sf.f._sbf._f._wide_data->_IO_write_ptr = '\0';

  return ret;
}
libc_hidden_def (__vswprintf_chk)
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include "../libio/libioP.h"


/* Write formatted output to stdout from the format string FORMAT.  */
int
__vwprintf_chk (int flag, const wchar_t *format, va_list ap)
{
  int done;

  _IO_acquire_lock_clear_flags2 (stdout);
  if (flag > 0)
    stdout->_flags2 |= _IO_FLAGS2_FORTIFY;

  done = _IO_vfwprintf (stdout, format, ap);

  if (flag > 0)
    stdout->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (stdout);

  return done;
}
/* Copyright (C) 1996-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1996.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>

#define __need_ptrdiff_t
#include <stddef.h>


/* Copy SRC to DEST, returning the address of the terminating L'\0' in
   DEST.  Check for overflows.  */
wchar_t *
__wcpcpy_chk (wchar_t *dest, const wchar_t *src, size_t destlen)
{
  wchar_t *wcp = (wchar_t *) dest - 1;
  wint_t c;
  const ptrdiff_t off = src - dest + 1;

  do
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      c = wcp[off];
      *++wcp = c;
    }
  while (c != L'\0');

  return wcp;
}
/* Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>


/* Copy no more than N wide-characters of SRC to DEST.	*/
wchar_t *
__wcpncpy_chk (wchar_t *dest, const wchar_t *src, size_t n, size_t destlen)
{
  if (__glibc_unlikely (destlen < n))
    __chk_fail ();

  /* This function is not often enough used to justify not using a
     tail call.  */
  return __wcpncpy (dest, src, n);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <langinfo.h>
#include <locale.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale/localeinfo.h>


size_t
__wcrtomb_chk (char *s, wchar_t wchar, mbstate_t *ps, size_t buflen)
{
  /* We do not have to implement the full wctomb semantics since we
     know that S cannot be NULL when we come here.  */
  if (buflen < MB_CUR_MAX)
    __chk_fail ();

  return __wcrtomb (s, wchar, ps);
}
/* Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>


/* Append SRC on the end of DEST.  Check for overflows.  */
wchar_t *
__wcscat_chk (wchar_t *dest, const wchar_t *src, size_t destlen)
{
  wchar_t *s1 = dest;
  const wchar_t *s2 = src;
  wchar_t c;

  /* Find the end of the string.  */
  do
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      c = *s1++;
    }
  while (c != L'\0');

  /* Make S1 point before the next character, so we can increment
     it while memory is read (wins on pipelined cpus).	*/
  s1 -= 2;
  ++destlen;

  do
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      c = *s2++;
      *++s1 = c;
    }
  while (c != L'\0');

  return dest;
}
/* Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stddef.h>
#include <wchar.h>


/* Copy SRC to DEST.  */
wchar_t *
__wcscpy_chk (wchar_t *dest, const wchar_t *src, size_t n)
{
  wint_t c;
  wchar_t *wcp;

  if (__alignof__ (wchar_t) >= sizeof (wchar_t))
    {
      const ptrdiff_t off = dest - src - 1;

      wcp = (wchar_t *) src;

      do
	{
	  if (__glibc_unlikely (n-- == 0))
	    __chk_fail ();
	  c = *wcp++;
	  wcp[off] = c;
	}
      while (c != L'\0');
    }
  else
    {
      wcp = dest;

      do
	{
	  if (__glibc_unlikely (n-- == 0))
	    __chk_fail ();
	  c = *src++;
	  *wcp++ = c;
	}
      while (c != L'\0');
    }

  return dest;
}
/* Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>


/* Append no more than N wide-character of SRC onto DEST.  */
wchar_t *
__wcsncat_chk (wchar_t *dest, const wchar_t *src, size_t n, size_t destlen)
{
  wchar_t c;
  wchar_t * const s = dest;

  /* Find the end of DEST.  */
  do
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      c = *dest++;
    }
  while (c != L'\0');

  /* Make DEST point before next character, so we can increment
     it while memory is read (wins on pipelined cpus).	*/
  ++destlen;
  dest -= 2;

  if (n >= 4)
    {
      size_t n4 = n >> 2;
      do
	{
	  if (__glibc_unlikely (destlen-- == 0))
	    __chk_fail ();
	  c = *src++;
	  *++dest = c;
	  if (c == L'\0')
	    return s;
	  if (__glibc_unlikely (destlen-- == 0))
	    __chk_fail ();
	  c = *src++;
	  *++dest = c;
	  if (c == L'\0')
	    return s;
	  if (__glibc_unlikely (destlen-- == 0))
	    __chk_fail ();
	  c = *src++;
	  *++dest = c;
	  if (c == L'\0')
	    return s;
	  if (__glibc_unlikely (destlen-- == 0))
	    __chk_fail ();
	  c = *src++;
	  *++dest = c;
	  if (c == L'\0')
	    return s;
	} while (--n4 > 0);
      n &= 3;
    }

  while (n > 0)
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      c = *src++;
      *++dest = c;
      if (c == L'\0')
	return s;
      n--;
    }

  if (c != L'\0')
    {
      if (__glibc_unlikely (destlen-- == 0))
	__chk_fail ();
      *++dest = L'\0';
    }

  return s;
}
/* Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>


/* Copy no more than N wide-characters of SRC to DEST.	*/
wchar_t *
__wcsncpy_chk (wchar_t *dest, const wchar_t *src, size_t n, size_t destlen)
{
  if (__glibc_unlikely (destlen < n))
    __chk_fail ();

  /* This function is not often enough used to justify not using a
     tail call.  */
  return __wcsncpy (dest, src, n);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <locale.h>
#include <wchar.h>


size_t
__wcsnrtombs_chk (char *dst, const wchar_t **src, size_t nwc, size_t len,
		  mbstate_t *ps, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  return __wcsnrtombs (dst, src, nwc, len, ps);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <locale.h>
#include <wchar.h>


size_t
__wcsrtombs_chk (char *dst, const wchar_t **src, size_t len,
		 mbstate_t *ps, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  return __wcsrtombs (dst, src, len, ps);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <locale.h>
#include <string.h>
#include <wchar.h>


size_t
__wcstombs_chk (char *dst, const wchar_t *src, size_t len, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < len))
    __chk_fail ();

  mbstate_t state;

  memset (&state, '\0', sizeof state);

  /* Return how many we wrote (or maybe an error).  */
  return __wcsrtombs (dst, &src, len, &state);
}
/* Copyright (C) 2005-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <locale.h>
#include <stdlib.h>
#include <wcsmbs/wcsmbsload.h>


extern mbstate_t __wctomb_state attribute_hidden; /* Defined in wctomb.c.  */


int
__wctomb_chk (char *s, wchar_t wchar, size_t buflen)
{
  /* We do not have to implement the full wctomb semantics since we
     know that S cannot be NULL when we come here.  */
  if (buflen < MB_CUR_MAX)
    __chk_fail ();

  return __wcrtomb (s, wchar, &__wctomb_state);
}
/* Copyright (C) 1996-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.org>, 1996.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>
#include <string.h>


wchar_t *
__wmemcpy_chk (wchar_t *s1, const wchar_t *s2, size_t n, size_t ns1)
{
  if (__glibc_unlikely (ns1 < n))
    __chk_fail ();
  return (wchar_t *) memcpy ((char *) s1, (char *) s2, n * sizeof (wchar_t));
}
/* Copyright (C) 1996-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper, <drepper@gnu.ai.mit.edu>

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>
#include <string.h>


wchar_t *
__wmemmove_chk (wchar_t *s1, const wchar_t *s2, size_t n, size_t ns1)
{
  if (__glibc_unlikely (ns1 < n))
    __chk_fail ();
  return (wchar_t *) memmove ((char *) s1, (char *) s2, n * sizeof (wchar_t));
}
/* Copyright (C) 1999-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.org>, 1999.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>
#include <string.h>


wchar_t *
__wmempcpy_chk (wchar_t *s1, const wchar_t *s2, size_t n, size_t ns1)
{
  if (__glibc_unlikely (ns1 < n))
    __chk_fail ();
  return (wchar_t *) __mempcpy ((char *) s1, (char *) s2,
				n * sizeof (wchar_t));
}
/* Copyright (C) 1996-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.org>, 1996.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <wchar.h>


wchar_t *
__wmemset_chk (wchar_t *s, wchar_t c, size_t n, size_t dstlen)
{
  if (__glibc_unlikely (dstlen < n))
    __chk_fail ();

  return wmemset (s, c, n);
}
/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include "../libio/libioP.h"


/* Write formatted output to stdout from the format string FORMAT.  */
int
__wprintf_chk (int flag, const wchar_t *format, ...)
{
  va_list ap;
  int done;

  _IO_acquire_lock_clear_flags2 (stdout);
  if (flag > 0)
    stdout->_flags2 |= _IO_FLAGS2_FORTIFY;

  va_start (ap, format);
  done = _IO_vfwprintf (stdout, format, ap);
  va_end (ap);

  if (flag > 0)
    stdout->_flags2 &= ~_IO_FLAGS2_FORTIFY;
  _IO_release_lock (stdout);

  return done;
}
