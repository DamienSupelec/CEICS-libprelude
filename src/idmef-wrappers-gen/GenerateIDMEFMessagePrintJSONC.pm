# Copyright (C) 2016-2018 CS-SI. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoannv@gmail.com>
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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package GenerateIDMEFMessagePrintJSONC;

use Generate;
@ISA = qw/Generate/;

use strict;
use IDMEFTree;

sub        header
{
    my        $self = shift;

    $self->output("
/*****
*
* Copyright (C) 2016-2018 CS-SI. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv\@gmail.com>
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

/* Auto-generated by the GenerateIDMEFMessagePrintJSONC package */

#include \"config.h\"
#include \"libmissing.h\"

#include <stdio.h>
#include <string.h>

#include \"idmef.h\"
#include \"idmef-tree-wrap.h\"
#include \"idmef-message-print-json.h\"


#define conv_uint8 conv_uint64
#define conv_uint16 conv_uint64
#define conv_uint32 conv_uint64
#define conv_int8 conv_int64
#define conv_int16 conv_int64
#define conv_int32 conv_int64


static int conv_uint64(prelude_io_t *fd, uint64_t value)
{
        int ret;
        char buf[32];

        ret = snprintf(buf, sizeof(buf), \"%\" PRELUDE_PRIu64, value);
        if ( ret < 0 || ret >= sizeof(buf) )
                return -1;

        return prelude_io_write(fd, buf, ret);
}


static int conv_int64(prelude_io_t *fd, int64_t value)
{
        int ret;
        char buf[32];

        ret = snprintf(buf, sizeof(buf), \"%\" PRELUDE_PRId64, value);
        if ( ret < 0 || ret >= sizeof(buf) )
                return -1;

        return prelude_io_write(fd, buf, ret);
}


static int conv_float(prelude_io_t *fd, float value)
{
        int ret;
        char buf[32];

        ret = snprintf(buf, sizeof(buf), \"%f\", value);
        if ( ret < 0 || ret >= sizeof(buf) )
                return -1;

        return prelude_io_write(fd, buf, ret);
}


static int conv_string(prelude_io_t *fd, prelude_string_t *string)
{
        size_t i;
        ssize_t ret;
        const unsigned char *content;

        content = (const unsigned char *) prelude_string_get_string_or_default(string, \"\");
        ret = prelude_io_write(fd, \"\\\"\", 1);
        if ( ret < 0 )
                return ret;

        for ( i = 0; i < prelude_string_get_len(string); i++, content++ ) {
                switch(*content) {
                        case '\\\\':
                        case '\"':
                        case '/':
                                ret = prelude_io_write(fd, \"\\\\\", 1);
                                if ( ret < 0 )
                                        return ret;

                                ret = prelude_io_write(fd, content, 1);
                                break;
                        case '\\b':
                                ret = prelude_io_write(fd, \"\\\\b\", 2);
                                break;
                        case '\\t':
                                ret = prelude_io_write(fd, \"\\\\t\", 2);
                                break;
                        case '\\n':
                                ret = prelude_io_write(fd, \"\\\\n\", 2);
                                break;
                        case '\\f':
                                ret = prelude_io_write(fd, \"\\\\f\", 2);
                                break;
                        case '\\r':
                                ret = prelude_io_write(fd, \"\\\\r\", 2);
                                break;
                        default:
                                if ( *content >= 0x20 )
                                        ret = prelude_io_write(fd, content, 1);
                                else {
                                        char seq[7];
                                        snprintf(seq, sizeof(seq), \"\\\\u%04X\", *content);
                                        ret = prelude_io_write(fd, seq, strlen(seq));
                                }
                }

                if ( ret < 0 )
                        return ret;
        }

        return prelude_io_write(fd, \"\\\"\", 1);
}


static int conv_time(prelude_io_t *fd, idmef_time_t *t)
{
        int ret;
        prelude_string_t *str;

        if ( ! t )
                return 0;

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                return ret;

        ret = idmef_time_to_string(t, str);
        if ( ret < 0 )
                goto error;

        ret = conv_string(fd, str);

error:
        prelude_string_destroy(str);
        return ret;
}


static int conv_data(prelude_io_t *fd, idmef_data_t *data)
{
        int ret;
        prelude_string_t *out;

        ret = prelude_string_new(&out);
        if ( ret < 0 )
                return ret;

        ret = idmef_data_to_string(data, out);
        if ( ret < 0 )
                goto error;

        switch (idmef_data_get_type(data)) {
                case IDMEF_DATA_TYPE_INT:
                case IDMEF_DATA_TYPE_FLOAT:
                        ret = prelude_io_write(fd, prelude_string_get_string(out), prelude_string_get_len(out));
                        break;
                default:
                        ret = conv_string(fd, out);
                        break;
        }
error:
        prelude_string_destroy(out);
        return ret;
}


static int do_write(prelude_io_t *fd, const char *str)
{
        return prelude_io_write(fd, str, strlen(str));
}
"
);
}

sub        struct_field_normal
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;
    my        $field = shift;
    my        $refer = "";

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
                        const char *enumstr = idmef_$field->{short_typename}_to_string(${refer}i);

                        if ( enumstr ) \{
                                ret = do_write(fd, \", \\\"$field->{short_name}\\\": \\\"\");
                                if ( ret < 0 )
                                        return ret;

                                ret = do_write(fd, enumstr);
                                if ( ret < 0 )
                                        return ret;

                                ret = do_write(fd, \"\\\"\");
                                if ( ret < 0 )
                                        return ret;
                        \}
                \}
        \}
");

    } elsif ( $field->{metatype} & &METATYPE_PRIMITIVE ) {
        if ( $field->{metatype} & (&METATYPE_STRUCT|&METATYPE_OPTIONAL_INT) ) {

            $self->output("
        \{
                $field->{typename} *field;

                field = idmef_$struct->{short_typename}_get_$field->{name}(ptr);
                if ( field ) \{
                        ret = do_write(fd, \", \\\"$field->{short_name}\\\": \");
                        if ( ret < 0 )
                                return ret;

                        ret = conv_$field->{value_type}(fd, ${refer}field);
                        if ( ret < 0 )
                                return ret;
                \}
        \}
");
        } else {
            $self->output("
        \{
                $field->{typename} field;

                field = idmef_$struct->{short_typename}_get_$field->{name}(ptr);
                if ( field ) \{
                        ret = do_write(fd, \", \\\"$field->{short_name}\\\": \");
                        if ( ret < 0 )
                                return ret;

                        ret = conv_$field->{value_type}(fd, ${refer}field);
                        if ( ret < 0 )
                                return ret;
                \}
        \}
");
        }
    } elsif ( $field->{metatype} & &METATYPE_STRUCT ) {
        $self->output("
        \{
                $field->{typename} *field;

                field = idmef_$struct->{short_typename}_get_$field->{name}(ptr);
                if ( field ) \{
                        ret = do_write(fd, \", \\\"$field->{short_name}\\\": \");
                        if ( ret < 0 )
                                return ret;

                        ret = idmef_$field->{short_typename}_print_json(field, fd);
                        if ( ret < 0 )
                                return ret;
                \}
        \}
");
    }
}

sub        struct_field_union
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;
    my        $field = shift;

    $self->output("
        switch ( idmef_$struct->{short_typename}_get_$field->{var}(ptr) ) \{");

    foreach my $member ( @{ $field->{member_list} } ) {
        $self->output("
        case $member->{value}:
                ret = do_write(fd, \", \\\"$member->{name}\\\": \");
                if ( ret < 0 )
                        return ret;

                ret = idmef_$member->{name}_print_json(idmef_$struct->{short_typename}_get_$member->{name}(ptr), fd);
                if ( ret < 0 )
                        return ret;
                break;
");
    }

    $self->output("
        default:
                break;
        \}
");

}

sub        struct_field_list
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;
    my        $field = shift;

    $self->output("
        \{

                $field->{typename} *elem = NULL;
                int first = 1;

                while ( (elem = idmef_$struct->{short_typename}_get_next_$field->{short_name}(ptr, elem)) ) \{
                        if ( ! first )
                                ret = do_write(fd, \", \");
                        else {
                                first = 0;
                                ret = do_write(fd, \", \\\"$field->{short_name}\\\": [\");
                        }

                        if ( ret < 0 )
                                return ret;

");

    if ( $field->{metatype} & &METATYPE_PRIMITIVE ) {
        $self->output("
                        ret = conv_$field->{value_type}(fd, elem);
                        if ( ret < 0 )
                                return ret;
");

    } else {
        $self->output("
                        ret = idmef_$field->{short_typename}_print_json(elem, fd);
                        if ( ret < 0 )
                                return ret;
");
    }

    $self->output("
                \}

                if ( ! first ) {
                        ret = do_write(fd, \"]\");
                        if ( ret < 0 )
                                return ret;
                }
        \}
");
}

sub        struct
{
    my        $self = shift;
    my        $tree = shift;
    my        $struct = shift;

    $self->output("

/**
 * idmef_$struct->{short_typename}_json:
 * \@ptr: Pointer to an $struct->{typename} object.
 *
 * This function will convert \@ptr to a json,
 */
int idmef_$struct->{short_typename}_print_json($struct->{typename} *ptr, prelude_io_t *fd)
\{
        int ret;

        if ( ! ptr )
                return 0;

        ret = do_write(fd, \"{\\\"_self\\\": \\\"$struct->{typename}\\\"\");
        if ( ret < 0 )
                return ret;

");

    foreach my $field ( @{ $struct->{field_list} } ) {

        if ( $field->{metatype} & &METATYPE_NORMAL ) {
            $self->struct_field_normal($tree, $struct, $field);

        } elsif ( $field->{metatype} & &METATYPE_UNION ) {
            $self->struct_field_union($tree, $struct, $field);

        } elsif ( $field->{metatype} & &METATYPE_LIST ) {
            $self->struct_field_list($tree, $struct, $field);
        }
    }

    $self->output("
        return do_write(fd, \"}\");\n}");
}

sub        footer
{
    my        $self = shift;
    my        $tree = shift;
}

1;
