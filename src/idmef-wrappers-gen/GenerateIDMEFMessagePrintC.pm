# Copyright (C) 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
# Author: Nicolas Delon <nicolas.delon@prelude-ids.com>
#
# This file is part of the Prelude library.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

package GenerateIDMEFMessagePrintC;

use Generate;
@ISA = qw/Generate/;

use strict;
use IDMEFTree; 

sub	header
{
    my	$self = shift;

    $self->output("
/*****
*
* Copyright (C) 2004,2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v\@prelude-ids.com>
* Author: Nicolas Delon <nicolas.delon\@prelude-ids.com>
*
* This file is part of the Prelude library.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

/* Auto-generated by the GenerateIDMEFMessagePrintC package */

#include \"config.h\"
#include \"libmissing.h\"

#include <stdio.h>
#include <time.h>

#include \"idmef.h\"
#include \"idmef-tree-wrap.h\"
#include \"idmef-message-print.h\"


static int indent = 0;

static void print_indent(prelude_io_t *fd)
\{
	int cnt;

	for ( cnt = 0; cnt < indent; cnt++ )
		prelude_io_write(fd, \" \", 1);
\}



static void print_string(prelude_string_t *string, prelude_io_t *fd)
\{
	const char *s;

	s = prelude_string_get_string(string);
        if ( ! s )
                s = \"<empty>\";

        prelude_io_write(fd, s, prelude_string_get_len(string));
\}



static void print_uint8(uint8_t i, prelude_io_t *fd)
\{
        int len;
        char buf[sizeof(\"255\")];
	
        /* 
         * %hh convertion specifier is not portable.
         */
        len = snprintf(buf, sizeof(buf), \"\%u\", (unsigned int) i);
        prelude_io_write(fd, buf, len);
\}


static void print_uint16(uint16_t i, prelude_io_t *fd)
\{
        int len;
        char buf[sizeof(\"65535\")];

	len = snprintf(buf, sizeof(buf), \"\%hu\", i);
        prelude_io_write(fd, buf, len);
\}


static void print_int32(int32_t i, prelude_io_t *fd)
\{
        int len;
        char buf[sizeof(\"4294967296\")];

	len = snprintf(buf, sizeof(buf), \"\%d\", i);
        prelude_io_write(fd, buf, len);
\}


static void print_uint32(uint32_t i, prelude_io_t *fd)
\{
        int len;
        char buf[sizeof(\"4294967296\")];

	len = snprintf(buf, sizeof(buf), \"\%u\", i);
        prelude_io_write(fd, buf, len);
\}



static void print_uint64(uint64_t i, prelude_io_t *fd)
\{
        int len;
        char buf[sizeof(\"18446744073709551616\")];

	len = snprintf(buf, sizeof(buf), \"%\" PRELUDE_PRIu64, i);
        prelude_io_write(fd, buf, len);
\}



static void print_float(float f, prelude_io_t *fd)
\{
        int len;
        char buf[32];

	len = snprintf(buf, sizeof(buf), \"\%f\", f);
        prelude_io_write(fd, buf, len);
\}




static void print_time(idmef_time_t *t, prelude_io_t *fd)
\{
        int len;
        time_t _time;
	struct tm _tm;
	char tmp[32], buf[128];

	_time = idmef_time_get_sec(t);

	if ( ! localtime_r(&_time, &_tm) )
		return;
        
        len = strftime(tmp, sizeof(tmp), \"%d/%m/%Y %H:%M:%S\", &_tm);
        if ( len == 0 ) 
                return;

        len = snprintf(buf, sizeof(buf), \"%s.%u %+.2d:%.2d\",
                       tmp, idmef_time_get_usec(t), idmef_time_get_gmt_offset(t) / 3600,
                       idmef_time_get_gmt_offset(t) % 3600 / 60);
   
        prelude_io_write(fd, buf, len);
\}



/* print data as a string */

static int print_data(idmef_data_t *data, prelude_io_t *fd)
\{
        int ret;
        prelude_string_t *out;

        ret = prelude_string_new(&out);
        if ( ret < 0 )
                return ret;

        ret = idmef_data_to_string(data, out);
	if ( ret < 0 ) {
                prelude_string_destroy(out);
		return ret;
        }

        prelude_io_write(fd, prelude_string_get_string(out), prelude_string_get_len(out));
        prelude_string_destroy(out);

        return 0;
\}



static void print_enum(const char *s, int i, prelude_io_t *fd)
\{
        int len;
        char buf[512];

	len = snprintf(buf, sizeof(buf), \"\%s (\%d)\", s, i);
        prelude_io_write(fd, buf, len);
\}

");
}

sub	struct_field_normal
{
    my	$self = shift;
    my	$tree = shift;
    my	$struct = shift;
    my	$field = shift;
    my	$refer = "";

    $refer = "*" if ( $field->{metatype} & &METATYPE_OPTIONAL_INT );

    if ( $field->{metatype} & &METATYPE_ENUM ) {
	$self->output("
	\{
		int ${refer}i = idmef_$struct->{short_typename}_get_$field->{name}(ptr);

");
	
	if ( $field->{metatype} & &METATYPE_OPTIONAL_INT ) {
	    $self->output("
		if ( i )
");
	}
	
	$self->output("

		\{
			print_indent(fd);
			prelude_io_write(fd, \"$field->{name}: \", sizeof(\"$field->{name}: \") - 1);
			print_enum(idmef_$field->{short_typename}_to_string(${refer}i), ${refer}i, fd);
			prelude_io_write(fd, \"\\n\", sizeof(\"\\n\") - 1);
		\}
        \}
");

    } elsif ( $field->{metatype} & &METATYPE_PRIMITIVE ) {

	if ( $field->{metatype} & (&METATYPE_STRUCT|&METATYPE_OPTIONAL_INT) ) {
	    $self->output("
	\{
		$field->{typename} *field;
                const char tmp[] = \"$field->{name}: \";

		field = idmef_$struct->{short_typename}_get_$field->{name}(ptr);

		if ( field ) \{
			print_indent(fd);
			prelude_io_write(fd, tmp, sizeof(tmp) - 1);
			print_$field->{value_type}(${refer}field, fd);
			prelude_io_write(fd, \"\\n\", sizeof(\"\\n\") - 1);
		\}
	\}
"); 

	} else {
	    $self->output("
	print_indent(fd);
	prelude_io_write(fd, \"$field->{name}: \", sizeof(\"$field->{name}: \") - 1);
	print_$field->{value_type}(idmef_$struct->{short_typename}_get_$field->{name}(ptr), fd);
	prelude_io_write(fd, \"\\n\", sizeof(\"\\n\") - 1);
");
	}

    } elsif ( $field->{metatype} & &METATYPE_STRUCT ) {
	$self->output("
	\{
		$field->{typename} *field;

		field = idmef_$struct->{short_typename}_get_$field->{name}(ptr);

		if ( field ) \{
			print_indent(fd);
			prelude_io_write(fd, \"$field->{name}:\\n\", sizeof(\"$field->{name}:\\n\") - 1);
			idmef_$field->{short_typename}_print(field, fd);
		\}
	\}	
");
    }
}

sub	struct_field_union
{
    my	$self = shift;
    my	$tree = shift;
    my	$struct = shift;
    my	$field = shift;

    $self->output("
	switch ( idmef_$struct->{short_typename}_get_$field->{var}(ptr) ) \{");

    foreach my $member ( @{ $field->{member_list} } ) {
	$self->output("
	case $member->{value}:
		print_indent(fd);
                prelude_io_write(fd, \"$member->{name}:\\n\", sizeof(\"$member->{name}:\\n\") - 1);
		idmef_$member->{short_typename}_print(idmef_$struct->{short_typename}_get_$member->{name}(ptr), fd);
		break;
 ");
    }

    $self->output("
	default:
		break;
	\}
");

}

sub	struct_field_list
{
    my	$self = shift;
    my	$tree = shift;
    my	$struct = shift;
    my	$field = shift;

    $self->output("
	\{
                char buf[128];
		$field->{typename} *elem = NULL;
		int cnt = 0, len;

		while ( (elem = idmef_$struct->{short_typename}_get_next_$field->{short_name}(ptr, elem)) ) \{
			print_indent(fd);
");

    if ( $field->{metatype} & &METATYPE_PRIMITIVE ) {
	$self->output("
                        len = snprintf(buf, sizeof(buf), \"$field->{short_name}(%d): \", cnt);
			prelude_io_write(fd, buf, len);
			print_$field->{value_type}(elem, fd);
                        prelude_io_write(fd, \"\\n\", sizeof(\"\\n\") - 1);
");

    } else {
	$self->output("
                        len = snprintf(buf, sizeof(buf), \"$field->{short_name}(%d): \\n\", cnt);
			prelude_io_write(fd, buf, len);
			idmef_$field->{short_typename}_print(elem, fd);
");
    }

    $self->output("
			cnt++;
		\}
	\}
");
}

sub	struct
{
    my	$self = shift;
    my	$tree = shift;
    my	$struct = shift;

    $self->output("
/**
 * idmef_$struct->{short_typename}_print:
 * \@ptr: Pointer to an $struct->{typename} object.
 * \@fd: Pointer to a #prelude_io_t object where to print \@ptr to.
 *
 * This function will convert \@ptr to a string suitable for writing,
 * and write it to the provided \@fd descriptor.
 */
void idmef_$struct->{short_typename}_print($struct->{typename} *ptr, prelude_io_t *fd)
\{
	if ( ! ptr )
		return;

");

    if ( $struct->{short_typename} ne "message" ) {
	$self->output("        indent += 8;\n");
    }

    foreach my $field ( @{ $struct->{field_list} } ) {

	if ( $field->{metatype} & &METATYPE_NORMAL ) {
	    $self->struct_field_normal($tree, $struct, $field);

	} elsif ( $field->{metatype} & &METATYPE_UNION ) {
	    $self->struct_field_union($tree, $struct, $field);

	} elsif ( $field->{metatype} & &METATYPE_LIST ) {
	    $self->struct_field_list($tree, $struct, $field);
	}
    }

    if ( $struct->{short_typename} ne "message" ) {
	$self->output("\n        indent -= 8;\n");
    }
    
    $self->output("}\n");
}

sub	footer
{
    my	$self = shift;
    my	$tree = shift;
}

1;
