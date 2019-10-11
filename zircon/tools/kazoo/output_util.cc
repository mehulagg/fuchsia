// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/kazoo/output_util.h"

#include <zircon/assert.h>
#include "tools/kazoo/string_util.h"

bool CopyrightHeaderWithCppComments(Writer* writer) {
  return writer->Puts(R"(// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// WARNING: THIS FILE IS MACHINE GENERATED BY //tools/kazoo. DO NOT EDIT.

)");
}

bool CopyrightHeaderWithHashComments(Writer* writer) {
  return writer->Puts(R"(# Copyright 2019 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# WARNING: THIS FILE IS MACHINE GENERATED BY //tools/kazoo. DO NOT EDIT.

)");
}

std::string ToLowerAscii(const std::string& input) {
  std::string ret = input;
  std::transform(ret.begin(), ret.end(), ret.begin(), ToLowerASCII);
  return ret;
}

std::string CamelToSnake(const std::string& camel_fidl) {
  auto is_transition = [](char prev, char cur, char peek) {
    enum { Upper, Lower, Other };
    auto categorize = [](char c) {
      if (c == 0)
        return Other;
      if (c >= 'a' && c <= 'z')
        return Lower;
      if (c >= 'A' && c <= 'Z')
        return Upper;
      if ((c >= '0' && c <= '9') || c == '_')
        return Other;
      ZX_ASSERT(false);
      return Other;
    };
    auto prev_type = categorize(prev);
    auto cur_type = categorize(cur);
    auto peek_type = categorize(peek);

    bool lower_to_upper = prev_type != Upper && cur_type == Upper;
    bool multiple_caps_to_lower =
        peek && (prev_type == Upper && cur_type == Upper && peek_type == Lower);

    return lower_to_upper || multiple_caps_to_lower;
  };
  std::vector<std::string> parts;
  char prev = 0;
  std::string current_word;
  for (size_t i = 0; i < camel_fidl.size(); ++i) {
    char cur = camel_fidl[i];
    char peek = i + 1 < camel_fidl.size() ? camel_fidl[i + 1] : 0;
    if (current_word.size() > 1 && is_transition(prev, cur, peek)) {
      parts.push_back(ToLowerAscii(current_word));
      current_word = cur;
    } else {
      current_word += cur;
    }
    prev = cur;
  }

  if (!current_word.empty()) {
    parts.push_back(ToLowerAscii(current_word));
  }

  return JoinStrings(parts, "_");
}

namespace {

// Most of the implementation of GetCUserModeName() and GetCKernelModeName(), other than for
// pointers.
std::string CNameImpl(const Type& type) {
  struct {
   public:
    void operator()(const std::monostate&) { ret = "<TODO!>"; }
    void operator()(const TypeBool&) { ret = "bool"; }
    void operator()(const TypeChar&) { ret = "char"; }
    void operator()(const TypeInt32&) { ret = "int32_t"; }
    void operator()(const TypeInt64&) { ret = "int64_t"; }
    void operator()(const TypeSizeT&) { ret = "size_t"; }
    void operator()(const TypeUint16&) { ret = "uint16_t"; }
    void operator()(const TypeUint32&) { ret = "uint32_t"; }
    void operator()(const TypeUint64&) { ret = "uint64_t"; }
    void operator()(const TypeUint8&) { ret = "uint8_t"; }
    void operator()(const TypeUintptrT&) { ret = "uintptr_t"; }
    void operator()(const TypeVoid&) { ret = "void"; }
    void operator()(const TypeZxBasicAlias& zx_basic_alias) { ret = zx_basic_alias.name(); }

    void operator()(const TypeEnum& enm) { ret = enm.enum_data().name(); }
    void operator()(const TypeHandle& handle) {
      ret = "zx_handle_t";
      // TOOD(syscall-fidl-transition): Once we're not trying to match abigen, it might be nice to
      // add the underlying handle type here like "zx_handle_t /*vmo*/ handle" or similar.
    }
    void operator()(const TypePointer& pointer) {
      ZX_ASSERT(false && "pointers should be handled by caller");
      ret = "<!>";
    }
    void operator()(const TypeString&) {
      ZX_ASSERT(false && "can't convert string to C directly");
      ret = "<!>";
    }
    void operator()(const TypeStruct& strukt) { ret = strukt.struct_data().name(); }
    void operator()(const TypeVector&) {
      ZX_ASSERT(false && "can't convert vector to C directly");
      ret = "<!>";
    }

    Constness constness;
    std::string ret;
  } name_visitor;
  name_visitor.constness = type.constness();
  std::visit(name_visitor, type.type_data());
  return name_visitor.ret;
}

}  // namespace

std::string GetCUserModeName(const Type& type) {
  if (type.IsPointer()) {
    ZX_ASSERT(type.constness() != Constness::kUnspecified &&
              "Pointer should be explictly const or mutable by output time");
    return (type.constness() == Constness::kConst ? "const " : "") +
           GetCUserModeName(type.DataAsPointer().pointed_to_type()) + "*";
  }
  return CNameImpl(type);
}

std::string GetCKernelModeName(const Type& type) {
  if (type.IsPointer()) {
    ZX_ASSERT(type.constness() != Constness::kUnspecified &&
              "Pointer should be explictly const or mutable by output time");
    std::string pointed_to = GetCKernelModeName(type.DataAsPointer().pointed_to_type());
    if (type.constness() == Constness::kConst) {
      return StringPrintf("user_in_ptr<const %s>", pointed_to.c_str());
    } else if (type.constness() == Constness::kMutable) {
      if (pointed_to == "zx_handle_t" && !type.DataAsPointer().was_vector()) {
        return "user_out_handle*";
      }
      if (type.optionality() == Optionality::kInputArgument) {
        return StringPrintf("user_inout_ptr<%s>", pointed_to.c_str());
      } else {
        return StringPrintf("user_out_ptr<%s>", pointed_to.c_str());
      }
    }
  }
  return CNameImpl(type);
}

JsonTypeNameData GetJsonName(const Type& type) {
  JsonTypeNameData ret;
  if (type.IsPointer()) {
    ret.name = GetCUserModeName(type.DataAsPointer().pointed_to_type());
    ret.is_pointer = true;
    if (type.constness() == Constness::kConst) {
      ret.attribute = "IN";
    } else if (type.constness() == Constness::kMutable) {
      if (type.optionality() == Optionality::kInputArgument) {
        ret.attribute = "INOUT";
      } else if (type.optionality() == Optionality::kOutputNonOptional) {
        ret.attribute = "OUT";
      } else if (type.optionality() == Optionality::kOutputOptional) {
        ret.attribute = "optional";
      }
    }

    if (ret.name == "void") {
      ret.name = "any";
    }
  } else {
    ret.name = GetCUserModeName(type);
  }
  return ret;
}

void CSignatureLine(const Syscall& syscall, const char* prefix, const char* name_prefix,
                    Writer* writer, SignatureNewlineStyle newline_style,
                    std::vector<std::string>* non_nulls) {
  const char* newline = newline_style == SignatureNewlineStyle::kAllOneLine ? "" : "\n";
  const char* indent = newline_style == SignatureNewlineStyle::kAllOneLine ? "" : "    ";
  writer->Puts(prefix);
  writer->Printf("%s ", GetCUserModeName(syscall.kernel_return_type()).c_str());
  writer->Printf("%s%s(%s", name_prefix, syscall.name().c_str(), newline);

  if (syscall.kernel_arguments().size() == 0) {
    if (newline_style == SignatureNewlineStyle::kOnePerLine) {
      writer->Puts(indent);
    }
    writer->Puts("void");
  } else {
    for (size_t i = 0; i < syscall.kernel_arguments().size(); ++i) {
      const StructMember& arg = syscall.kernel_arguments()[i];
      const bool last = i == syscall.kernel_arguments().size() - 1;
      if (newline_style == SignatureNewlineStyle::kOnePerLine) {
        writer->Puts("    ");  // All indented if one per line.
      } else if (i != 0) {
        writer->Puts(" ");  // No space after open ( for single line.
      }
      writer->Printf("%s %s", GetCUserModeName(arg.type()).c_str(), arg.name().c_str());
      if (!last) {
        writer->Printf(",%s", newline);
      }
      if (arg.type().IsPointer() && arg.type().optionality() == Optionality::kOutputNonOptional) {
        if (non_nulls) {
          non_nulls->push_back(StringPrintf("%zu", i + 1));
        }
      }
    }
  }
  writer->Printf(")");
}

void CDeclaration(const Syscall& syscall, const char* prefix, const char* name_prefix,
                  Writer* writer) {
  std::vector<std::string> non_nulls;
  CSignatureLine(syscall, prefix, name_prefix, writer, SignatureNewlineStyle::kOnePerLine,
                 &non_nulls);

  // TODO(syscall-fidl-transition): The order of these post-declaration markup is maintained, but
  // perhaps it could be simplified once it doesn't need to match.

  if (!non_nulls.empty()) {
    // TODO(syscall-fidl-transition): abigen only tags non-optional arguments as non-null, but
    // other input pointers could also perhaps be usefully tagged as well.
    writer->Printf(" __NONNULL((%s))", JoinStrings(non_nulls, ", ").c_str());
  }
  writer->Printf(" __LEAF_FN");
  if (syscall.HasAttribute("Const")) {
    writer->Puts(" __CONST");
  }
  if (syscall.HasAttribute("Noreturn")) {
    writer->Puts(" __NO_RETURN");
  }
  writer->Puts(";\n\n");
}