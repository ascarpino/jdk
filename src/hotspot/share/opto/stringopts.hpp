/*
 * Copyright (c) 2009, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#ifndef SHARE_OPTO_STRINGOPTS_HPP
#define SHARE_OPTO_STRINGOPTS_HPP

#include "opto/node.hpp"
#include "opto/phaseX.hpp"

class StringConcat;
class IdealVariable;

class PhaseStringOpts : public Phase {
  friend class StringConcat;

private:
  PhaseGVN* _gvn;

  // List of dead nodes to clean up aggressively at the end
  Unique_Node_List dead_worklist;

  // Memory slices needed for code gen
  int byte_adr_idx;

  // A set for use by various stages
  VectorSet _visited;

  // Collect a list of all SB.toString calls
  Node_List collect_toString_calls();

  // Examine the use of the SB alloc to see if it can be replace with
  // a single string construction.
  StringConcat* build_candidate(CallStaticJavaNode* call);

  enum class ProcessAppendResult {
    // Indicates that the candidate was indeed an append and process_append_candidate processed it
    // accordingly (added it to the StringConcat etc.)
    AppendWasAdded,
    // The candidate turned out not to be an append call. process_append_candidate did not do anything.
    CandidateIsNotAppend,
    // The candidate is an append call, but circumstances completely preventing string concat
    // optimization were detected and the optimization must abort.
    AbortOptimization
  };

  // Called from build_candidate. Looks at an "append candidate", a call that might be a call
  // to StringBuilder::append. If so, adds it to the StringConcat.
  ProcessAppendResult process_append_candidate(CallStaticJavaNode* cnode, StringConcat* sc,
                                               ciMethod* m, ciSymbol* string_sig, ciSymbol* int_sig,
                                               ciSymbol* char_sig);

  // Replace all the SB calls in concat with an optimization String allocation
  void replace_string_concat(StringConcat* concat);

  // Compute the number of characters required to represent the int value
  Node* int_stringSize(GraphKit& kit, Node* value);

  // Simplified version of Integer.getChars
  void getChars(GraphKit& kit, Node* arg, Node* dst_array, BasicType bt, Node* end, Node* final_merge, Node* final_mem, int merge_index = 0);

  // Copy the characters representing arg into dst_array starting at start
  Node* int_getChars(GraphKit& kit, Node* arg, Node* dst_array, Node* dst_coder, Node* start, Node* size);

  // Copy contents of the String str into dst_array starting at index start.
  Node* copy_string(GraphKit& kit, Node* str, Node* dst_array, Node* dst_coder, Node* start);

  // Copy 'count' bytes/chars from src_array to dst_array starting at index start
  void arraycopy(GraphKit& kit, IdealKit& ideal, Node* src_array, Node* dst_array, BasicType elembt, Node* start, Node* count);

  // Copy contents of constant src_array to dst_array by emitting individual stores
  void copy_constant_string(GraphKit& kit, IdealKit& ideal, ciTypeArray* src_array, IdealVariable& count,
                            bool src_is_byte, Node* dst_array, Node* dst_coder, Node* start);

  // Copy contents of a Latin1 encoded string from src_array to dst_array
  void copy_latin1_string(GraphKit& kit, IdealKit& ideal, Node* src_array, IdealVariable& count,
                          Node* dst_array, Node* dst_coder, Node* start);

  // Copy the char into dst_array at index start.
  Node* copy_char(GraphKit& kit, Node* val, Node* dst_array, Node* dst_coder, Node* start);

  // Allocate a byte array of specified length.
  Node* allocate_byte_array(GraphKit& kit, IdealKit* ideal, Node* length);

  // Returns the coder of a constant string
  jbyte get_constant_coder(GraphKit& kit, Node* str);

  // Returns the length of a constant string
  int get_constant_length(GraphKit& kit, Node* str);

  // Returns the value array of a constant string
  ciTypeArray* get_constant_value(GraphKit& kit, Node* str);

  // Clean up any leftover nodes
  void record_dead_node(Node* node);
  void remove_dead_nodes();

  PhaseGVN* gvn() { return _gvn; }

  enum {
    // max length of constant string copy unrolling in copy_string
    unroll_string_copy_length = 6
  };

public:
  PhaseStringOpts(PhaseGVN* gvn);

#ifndef PRODUCT
  static void print_statistics();

private:
  static uint _stropts_replaced;
  static uint _stropts_merged;
  static uint _stropts_total;
#endif
};

#endif // SHARE_OPTO_STRINGOPTS_HPP
