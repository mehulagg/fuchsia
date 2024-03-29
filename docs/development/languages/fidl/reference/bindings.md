# FIDL bindings specification

This document is a specification of requirements on the Fuchsia Interface
Definition Language (**FIDL**) bindings.

In this document, the following keywords are to be interpreted as described in
[RFC2119][RFC2119]: **MAY**, **MUST**, **MUST NOT**, **OPTIONAL**,
**RECOMMENDED**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**.

## Requirements

Items described in this section **MUST** be met for bindings to be considered
conformant.

### Generated Code Indication

A comment must be placed at the top of machine-generated code to indicate it is
machine generated.
For languages with a standard on how to indicate generated sources (as opposed
to human-written code), that standard must be followed..

In [Go][go-generated-code-comment] for instance, generated sources must be marked
with a comment following the pattern

```go
// Code generated by <tool>; DO NOT EDIT.
```

## Recommendations

Items described in this section **SHOULD** be met for bindings to be considered
conformant.

_TODO_

## Best Practices

Items described in this section **MAY** be met for bindings to be considered
conformant.

### Bits Support

It is RECOMMENDED to support the following operators over generated values:

* bitwise and, i.e `&`
* bitwise or, i.e `|`
* bitwise exclusive-or, i.e `^`
* bitwise not, i.e `~`

To provide bitwise operations which always result in valid bits values,
implementations of bitwise not should further mask the resulting value with
the mask of all values. In pseudo code:

```
~value1   means   mask & ~bits_of(value1)
```

This mask value is provided in the [JSON IR][jsonir] for convenience.

Bindings SHOULD NOT support other operators since they could result in
invalid bits value (or risk a non-obvious translation of their meaning), e.g.:

* bitwise shifts, i.e `<<` or `>>`
* bitwise unsigned shift, i.e `>>>`

### Union Support

_This section applies to flexible unions as well as the soon to be deprecated
unions_

For languages without union types and literals for these, it is RECOMMENDED to
support factory methods for constructing new unions/xunions given a value for
one of the possible variants. For example, in a C like language, this would
allow replacing code like:

```C
my_union_t foo;
foo.set_variant(bar);
do_stuff(foo);
```

with something like:

```C
do_stuff(my_union_with_variant(bar));
```

Examples of this for the
[HLCPP](https://fuchsia-review.googlesource.com/c/fuchsia/+/309246/) and
[Go](https://fuchsia-review.googlesource.com/c/fuchsia/+/313205/) bindings.

## Related Documents

* [FTP-024: Mandatory Source Compatibility][ftp024]

<!-- xrefs -->
[jsonir]: /docs/development/languages/fidl/reference/json-ir.md
[ftp024]: /docs/development/languages/fidl/reference/ftp/ftp-024.md
[RFC2119]: https://tools.ietf.org/html/rfc2119
[go-generated-code-comment]: https://github.com/golang/go/issues/13560#issuecomment-288457920
