/*
 * Copyright (c) 1997, 2025, Oracle and/or its affiliates. All rights reserved.
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

#include "cds/aotConstantPoolResolver.hpp"
#include "cds/archiveBuilder.hpp"
#include "cds/archiveHeapLoader.hpp"
#include "cds/archiveHeapWriter.hpp"
#include "cds/cdsConfig.hpp"
#include "cds/heapShared.hpp"
#include "classfile/classLoader.hpp"
#include "classfile/classLoaderData.hpp"
#include "classfile/javaClasses.inline.hpp"
#include "classfile/metadataOnStackMark.hpp"
#include "classfile/stringTable.hpp"
#include "classfile/systemDictionary.hpp"
#include "classfile/systemDictionaryShared.hpp"
#include "classfile/vmClasses.hpp"
#include "classfile/vmSymbols.hpp"
#include "code/codeCache.hpp"
#include "interpreter/bootstrapInfo.hpp"
#include "interpreter/linkResolver.hpp"
#include "jvm.h"
#include "logging/log.hpp"
#include "logging/logStream.hpp"
#include "memory/allocation.inline.hpp"
#include "memory/metadataFactory.hpp"
#include "memory/metaspaceClosure.hpp"
#include "memory/oopFactory.hpp"
#include "memory/resourceArea.hpp"
#include "memory/universe.hpp"
#include "oops/array.hpp"
#include "oops/constantPool.inline.hpp"
#include "oops/cpCache.inline.hpp"
#include "oops/fieldStreams.inline.hpp"
#include "oops/instanceKlass.hpp"
#include "oops/klass.inline.hpp"
#include "oops/objArrayKlass.hpp"
#include "oops/objArrayOop.inline.hpp"
#include "oops/oop.inline.hpp"
#include "oops/typeArrayOop.inline.hpp"
#include "prims/jvmtiExport.hpp"
#include "runtime/atomic.hpp"
#include "runtime/fieldDescriptor.inline.hpp"
#include "runtime/handles.inline.hpp"
#include "runtime/init.hpp"
#include "runtime/javaCalls.hpp"
#include "runtime/javaThread.inline.hpp"
#include "runtime/perfData.hpp"
#include "runtime/signature.hpp"
#include "runtime/vframe.inline.hpp"
#include "utilities/checkedCast.hpp"
#include "utilities/copy.hpp"

ConstantPool* ConstantPool::allocate(ClassLoaderData* loader_data, int length, TRAPS) {
  Array<u1>* tags = MetadataFactory::new_array<u1>(loader_data, length, 0, CHECK_NULL);
  int size = ConstantPool::size(length);
  return new (loader_data, size, MetaspaceObj::ConstantPoolType, THREAD) ConstantPool(tags);
}

void ConstantPool::copy_fields(const ConstantPool* orig) {
  // Preserve dynamic constant information from the original pool
  if (orig->has_dynamic_constant()) {
    set_has_dynamic_constant();
  }

  set_major_version(orig->major_version());
  set_minor_version(orig->minor_version());

  set_source_file_name_index(orig->source_file_name_index());
  set_generic_signature_index(orig->generic_signature_index());
}

#ifdef ASSERT

// MetaspaceObj allocation invariant is calloc equivalent memory
// simple verification of this here (JVM_CONSTANT_Invalid == 0 )
static bool tag_array_is_zero_initialized(Array<u1>* tags) {
  assert(tags != nullptr, "invariant");
  const int length = tags->length();
  for (int index = 0; index < length; ++index) {
    if (JVM_CONSTANT_Invalid != tags->at(index)) {
      return false;
    }
  }
  return true;
}

#endif

ConstantPool::ConstantPool() {
  assert(CDSConfig::is_dumping_static_archive() || CDSConfig::is_using_archive(), "only for CDS");
}

ConstantPool::ConstantPool(Array<u1>* tags) :
  _tags(tags),
  _length(tags->length()) {

    assert(_tags != nullptr, "invariant");
    assert(tags->length() == _length, "invariant");
    assert(tag_array_is_zero_initialized(tags), "invariant");
    assert(0 == flags(), "invariant");
    assert(0 == version(), "invariant");
    assert(nullptr == _pool_holder, "invariant");
}

void ConstantPool::deallocate_contents(ClassLoaderData* loader_data) {
  if (cache() != nullptr) {
    MetadataFactory::free_metadata(loader_data, cache());
    set_cache(nullptr);
  }

  MetadataFactory::free_array<Klass*>(loader_data, resolved_klasses());
  set_resolved_klasses(nullptr);

  MetadataFactory::free_array<jushort>(loader_data, operands());
  set_operands(nullptr);

  release_C_heap_structures();

  // free tag array
  MetadataFactory::free_array<u1>(loader_data, tags());
  set_tags(nullptr);
}

void ConstantPool::release_C_heap_structures() {
  // walk constant pool and decrement symbol reference counts
  unreference_symbols();
}

void ConstantPool::metaspace_pointers_do(MetaspaceClosure* it) {
  log_trace(aot)("Iter(ConstantPool): %p", this);

  it->push(&_tags, MetaspaceClosure::_writable);
  it->push(&_cache);
  it->push(&_pool_holder);
  it->push(&_operands);
  it->push(&_resolved_klasses, MetaspaceClosure::_writable);

  for (int i = 0; i < length(); i++) {
    // The only MSO's embedded in the CP entries are Symbols:
    //   JVM_CONSTANT_String
    //   JVM_CONSTANT_Utf8
    constantTag ctag = tag_at(i);
    if (ctag.is_string() || ctag.is_utf8()) {
      it->push(symbol_at_addr(i));
    }
  }
}

objArrayOop ConstantPool::resolved_references() const {
  return _cache->resolved_references();
}

// Called from outside constant pool resolution where a resolved_reference array
// may not be present.
objArrayOop ConstantPool::resolved_references_or_null() const {
  if (_cache == nullptr) {
    return nullptr;
  } else {
    return _cache->resolved_references();
  }
}

oop ConstantPool::resolved_reference_at(int index) const {
  oop result = resolved_references()->obj_at(index);
  assert(oopDesc::is_oop_or_null(result), "Must be oop");
  return result;
}

// Use a CAS for multithreaded access
oop ConstantPool::set_resolved_reference_at(int index, oop new_result) {
  assert(oopDesc::is_oop_or_null(new_result), "Must be oop");
  return resolved_references()->replace_if_null(index, new_result);
}

// Create resolved_references array and mapping array for original cp indexes
// The ldc bytecode was rewritten to have the resolved reference array index so need a way
// to map it back for resolving and some unlikely miscellaneous uses.
// The objects created by invokedynamic are appended to this list.
void ConstantPool::initialize_resolved_references(ClassLoaderData* loader_data,
                                                  const intStack& reference_map,
                                                  int constant_pool_map_length,
                                                  TRAPS) {
  // Initialized the resolved object cache.
  int map_length = reference_map.length();
  if (map_length > 0) {
    // Only need mapping back to constant pool entries.  The map isn't used for
    // invokedynamic resolved_reference entries.  For invokedynamic entries,
    // the constant pool cache index has the mapping back to both the constant
    // pool and to the resolved reference index.
    if (constant_pool_map_length > 0) {
      Array<u2>* om = MetadataFactory::new_array<u2>(loader_data, constant_pool_map_length, CHECK);

      for (int i = 0; i < constant_pool_map_length; i++) {
        int x = reference_map.at(i);
        assert(x == (int)(jushort) x, "klass index is too big");
        om->at_put(i, (jushort)x);
      }
      set_reference_map(om);
    }

    // Create Java array for holding resolved strings, methodHandles,
    // methodTypes, invokedynamic and invokehandle appendix objects, etc.
    objArrayOop stom = oopFactory::new_objArray(vmClasses::Object_klass(), map_length, CHECK);
    HandleMark hm(THREAD);
    Handle refs_handle (THREAD, stom);  // must handleize.
    set_resolved_references(loader_data->add_handle(refs_handle));

    // Create a "scratch" copy of the resolved references array to archive
    if (CDSConfig::is_dumping_heap()) {
      objArrayOop scratch_references = oopFactory::new_objArray(vmClasses::Object_klass(), map_length, CHECK);
      HeapShared::add_scratch_resolved_references(this, scratch_references);
    }
  }
}

void ConstantPool::allocate_resolved_klasses(ClassLoaderData* loader_data, int num_klasses, TRAPS) {
  // A ConstantPool can't possibly have 0xffff valid class entries,
  // because entry #0 must be CONSTANT_Invalid, and each class entry must refer to a UTF8
  // entry for the class's name. So at most we will have 0xfffe class entries.
  // This allows us to use 0xffff (ConstantPool::_temp_resolved_klass_index) to indicate
  // UnresolvedKlass entries that are temporarily created during class redefinition.
  assert(num_klasses < CPKlassSlot::_temp_resolved_klass_index, "sanity");
  assert(resolved_klasses() == nullptr, "sanity");
  Array<Klass*>* rk = MetadataFactory::new_array<Klass*>(loader_data, num_klasses, CHECK);
  set_resolved_klasses(rk);
}

void ConstantPool::initialize_unresolved_klasses(ClassLoaderData* loader_data, TRAPS) {
  int len = length();
  int num_klasses = 0;
  for (int i = 1; i <len; i++) {
    switch (tag_at(i).value()) {
    case JVM_CONSTANT_ClassIndex:
      {
        const int class_index = klass_index_at(i);
        unresolved_klass_at_put(i, class_index, num_klasses++);
      }
      break;
#ifndef PRODUCT
    case JVM_CONSTANT_Class:
    case JVM_CONSTANT_UnresolvedClass:
    case JVM_CONSTANT_UnresolvedClassInError:
      // All of these should have been reverted back to ClassIndex before calling
      // this function.
      ShouldNotReachHere();
#endif
    }
  }
  allocate_resolved_klasses(loader_data, num_klasses, THREAD);
}

// Hidden class support:
void ConstantPool::klass_at_put(int class_index, Klass* k) {
  assert(k != nullptr, "must be valid klass");
  CPKlassSlot kslot = klass_slot_at(class_index);
  int resolved_klass_index = kslot.resolved_klass_index();
  Klass** adr = resolved_klasses()->adr_at(resolved_klass_index);
  Atomic::release_store(adr, k);

  // The interpreter assumes when the tag is stored, the klass is resolved
  // and the Klass* non-null, so we need hardware store ordering here.
  release_tag_at_put(class_index, JVM_CONSTANT_Class);
}

#if INCLUDE_CDS_JAVA_HEAP
template <typename Function>
void ConstantPool::iterate_archivable_resolved_references(Function function) {
  objArrayOop rr = resolved_references();
  if (rr != nullptr && cache() != nullptr && CDSConfig::is_dumping_method_handles()) {
    Array<ResolvedIndyEntry>* indy_entries = cache()->resolved_indy_entries();
    if (indy_entries != nullptr) {
      for (int i = 0; i < indy_entries->length(); i++) {
        ResolvedIndyEntry *rie = indy_entries->adr_at(i);
        if (rie->is_resolved() && AOTConstantPoolResolver::is_resolution_deterministic(this, rie->constant_pool_index())) {
          int rr_index = rie->resolved_references_index();
          assert(resolved_reference_at(rr_index) != nullptr, "must exist");
          function(rr_index);

          // Save the BSM as well (sometimes the JIT looks up the BSM it for replay)
          int indy_cp_index = rie->constant_pool_index();
          int bsm_mh_cp_index = bootstrap_method_ref_index_at(indy_cp_index);
          int bsm_rr_index = cp_to_object_index(bsm_mh_cp_index);
          assert(resolved_reference_at(bsm_rr_index) != nullptr, "must exist");
          function(bsm_rr_index);
        }
      }
    }

    Array<ResolvedMethodEntry>* method_entries = cache()->resolved_method_entries();
    if (method_entries != nullptr) {
      for (int i = 0; i < method_entries->length(); i++) {
        ResolvedMethodEntry* rme = method_entries->adr_at(i);
        if (rme->is_resolved(Bytecodes::_invokehandle) && rme->has_appendix() &&
            cache()->can_archive_resolved_method(this, rme)) {
          int rr_index = rme->resolved_references_index();
          assert(resolved_reference_at(rr_index) != nullptr, "must exist");
          function(rr_index);
        }
      }
    }
  }
}

// Returns the _resolved_reference array after removing unarchivable items from it.
// Returns null if this class is not supported, or _resolved_reference doesn't exist.
objArrayOop ConstantPool::prepare_resolved_references_for_archiving() {
  if (_cache == nullptr) {
    return nullptr; // nothing to do
  }

  InstanceKlass *ik = pool_holder();
  if (!SystemDictionaryShared::is_builtin_loader(ik->class_loader_data())) {
    // Archiving resolved references for classes from non-builtin loaders
    // is not yet supported.
    return nullptr;
  }

  objArrayOop rr = resolved_references();
  if (rr != nullptr) {
    ResourceMark rm;
    int rr_len = rr->length();
    GrowableArray<bool> keep_resolved_refs(rr_len, rr_len, false);

    iterate_archivable_resolved_references([&](int rr_index) {
      keep_resolved_refs.at_put(rr_index, true);
    });

    objArrayOop scratch_rr = HeapShared::scratch_resolved_references(this);
    Array<u2>* ref_map = reference_map();
    int ref_map_len = ref_map == nullptr ? 0 : ref_map->length();
    for (int i = 0; i < rr_len; i++) {
      oop obj = rr->obj_at(i);
      scratch_rr->obj_at_put(i, nullptr);
      if (obj != nullptr) {
        if (i < ref_map_len) {
          int index = object_to_cp_index(i);
          if (tag_at(index).is_string()) {
            assert(java_lang_String::is_instance(obj), "must be");
            if (!ArchiveHeapWriter::is_string_too_large_to_archive(obj)) {
              scratch_rr->obj_at_put(i, obj);
            }
            continue;
          }
        }

        if (keep_resolved_refs.at(i)) {
          scratch_rr->obj_at_put(i, obj);
        }
      }
    }
    return scratch_rr;
  }
  return rr;
}
#endif

#if INCLUDE_CDS
// CDS support. Create a new resolved_references array.
void ConstantPool::restore_unshareable_info(TRAPS) {
  if (!_pool_holder->is_linked() && !_pool_holder->is_rewritten()) {
    return;
  }
  assert(is_constantPool(), "ensure C++ vtable is restored");
  assert(on_stack(), "should always be set for shared constant pools");
  assert(is_shared(), "should always be set for shared constant pools");
  if (is_for_method_handle_intrinsic()) {
    // See the same check in remove_unshareable_info() below.
    assert(cache() == nullptr, "must not have cpCache");
    return;
  }
  assert(_cache != nullptr, "constant pool _cache should not be null");

  // Only create the new resolved references array if it hasn't been attempted before
  if (resolved_references() != nullptr) return;

  if (vmClasses::Object_klass_loaded()) {
    ClassLoaderData* loader_data = pool_holder()->class_loader_data();
#if INCLUDE_CDS_JAVA_HEAP
    if (ArchiveHeapLoader::is_in_use() &&
        _cache->archived_references() != nullptr) {
      oop archived = _cache->archived_references();
      // Create handle for the archived resolved reference array object
      HandleMark hm(THREAD);
      Handle refs_handle(THREAD, archived);
      set_resolved_references(loader_data->add_handle(refs_handle));
      _cache->clear_archived_references();
    } else
#endif
    {
      // No mapped archived resolved reference array
      // Recreate the object array and add to ClassLoaderData.
      int map_length = resolved_reference_length();
      if (map_length > 0) {
        objArrayOop stom = oopFactory::new_objArray(vmClasses::Object_klass(), map_length, CHECK);
        HandleMark hm(THREAD);
        Handle refs_handle(THREAD, stom);  // must handleize.
        set_resolved_references(loader_data->add_handle(refs_handle));
      }
    }
  }

  if (CDSConfig::is_dumping_final_static_archive() && CDSConfig::is_dumping_heap() && resolved_references() != nullptr) {
    objArrayOop scratch_references = oopFactory::new_objArray(vmClasses::Object_klass(), resolved_references()->length(), CHECK);
    HeapShared::add_scratch_resolved_references(this, scratch_references);
  }
}

void ConstantPool::remove_unshareable_info() {
  // Shared ConstantPools are in the RO region, so the _flags cannot be modified.
  // The _on_stack flag is used to prevent ConstantPools from deallocation during
  // class redefinition. Since shared ConstantPools cannot be deallocated anyway,
  // we always set _on_stack to true to avoid having to change _flags during runtime.
  _flags |= (_on_stack | _is_shared);

  if (is_for_method_handle_intrinsic()) {
    // This CP was created by Method::make_method_handle_intrinsic() and has nothing
    // that need to be removed/restored. It has no cpCache since the intrinsic methods
    // don't have any bytecodes.
    assert(cache() == nullptr, "must not have cpCache");
    return;
  }

  bool update_resolved_reference = true;
  if (CDSConfig::is_dumping_final_static_archive()) {
    ConstantPool* src_cp = ArchiveBuilder::current()->get_source_addr(this);
    InstanceKlass* src_holder = src_cp->pool_holder();
    if (src_holder->defined_by_other_loaders()) {
      // Unregistered classes are not loaded in the AOT assembly phase. The resolved reference length
      // is already saved during the training run.
      precond(!src_holder->is_loaded());
      precond(resolved_reference_length() >= 0);
      precond(resolved_references() == nullptr);
      update_resolved_reference = false;
    }
  }

  // resolved_references(): remember its length. If it cannot be restored
  // from the archived heap objects at run time, we need to dynamically allocate it.
  if (update_resolved_reference && cache() != nullptr) {
    set_resolved_reference_length(
        resolved_references() != nullptr ? resolved_references()->length() : 0);
    set_resolved_references(OopHandle());
  }
  remove_unshareable_entries();
}

static const char* get_type(Klass* k) {
  const char* type;
  Klass* src_k;
  if (ArchiveBuilder::is_active() && ArchiveBuilder::current()->is_in_buffer_space(k)) {
    src_k = ArchiveBuilder::current()->get_source_addr(k);
  } else {
    src_k = k;
  }

  if (src_k->is_objArray_klass()) {
    src_k = ObjArrayKlass::cast(src_k)->bottom_klass();
    assert(!src_k->is_objArray_klass(), "sanity");
  }

  if (src_k->is_typeArray_klass()) {
    type = "prim";
  } else {
    InstanceKlass* src_ik = InstanceKlass::cast(src_k);
    if (src_ik->defined_by_boot_loader()) {
      return "boot";
    } else if (src_ik->defined_by_platform_loader()) {
      return "plat";
    } else if (src_ik->defined_by_app_loader()) {
      return "app";
    } else {
      return "unreg";
    }
  }

  return type;
}

void ConstantPool::remove_unshareable_entries() {
  ResourceMark rm;
  log_info(aot, resolve)("Archiving CP entries for %s", pool_holder()->name()->as_C_string());
  for (int cp_index = 1; cp_index < length(); cp_index++) { // cp_index 0 is unused
    int cp_tag = tag_at(cp_index).value();
    switch (cp_tag) {
    case JVM_CONSTANT_UnresolvedClass:
      ArchiveBuilder::alloc_stats()->record_klass_cp_entry(false, false);
      break;
    case JVM_CONSTANT_UnresolvedClassInError:
      tag_at_put(cp_index, JVM_CONSTANT_UnresolvedClass);
      ArchiveBuilder::alloc_stats()->record_klass_cp_entry(false, true);
      break;
    case JVM_CONSTANT_MethodHandleInError:
      tag_at_put(cp_index, JVM_CONSTANT_MethodHandle);
      break;
    case JVM_CONSTANT_MethodTypeInError:
      tag_at_put(cp_index, JVM_CONSTANT_MethodType);
      break;
    case JVM_CONSTANT_DynamicInError:
      tag_at_put(cp_index, JVM_CONSTANT_Dynamic);
      break;
    case JVM_CONSTANT_Class:
      remove_resolved_klass_if_non_deterministic(cp_index);
      break;
    default:
      break;
    }
  }

  if (cache() != nullptr) {
    // cache() is null if this class is not yet linked.
    cache()->remove_unshareable_info();
  }
}

void ConstantPool::remove_resolved_klass_if_non_deterministic(int cp_index) {
  assert(ArchiveBuilder::current()->is_in_buffer_space(this), "must be");
  assert(tag_at(cp_index).is_klass(), "must be resolved");

  Klass* k = resolved_klass_at(cp_index);
  bool can_archive;

  if (k == nullptr) {
    // We'd come here if the referenced class has been excluded via
    // SystemDictionaryShared::is_excluded_class(). As a result, ArchiveBuilder
    // has cleared the resolved_klasses()->at(...) pointer to null. Thus, we
    // need to revert the tag to JVM_CONSTANT_UnresolvedClass.
    can_archive = false;
  } else {
    ConstantPool* src_cp = ArchiveBuilder::current()->get_source_addr(this);
    can_archive = AOTConstantPoolResolver::is_resolution_deterministic(src_cp, cp_index);
  }

  if (!can_archive) {
    int resolved_klass_index = klass_slot_at(cp_index).resolved_klass_index();
    // This might be at a safepoint but do this in the right order.
    tag_at_put(cp_index, JVM_CONSTANT_UnresolvedClass);
    resolved_klasses()->at_put(resolved_klass_index, nullptr);
  }

  LogStreamHandle(Trace, aot, resolve) log;
  if (log.is_enabled()) {
    ResourceMark rm;
    log.print("%s klass  CP entry [%3d]: %s %s",
              (can_archive ? "archived" : "reverted"),
              cp_index, pool_holder()->name()->as_C_string(), get_type(pool_holder()));
    if (can_archive) {
      log.print(" => %s %s%s", k->name()->as_C_string(), get_type(k),
                (!k->is_instance_klass() || pool_holder()->is_subtype_of(k)) ? "" : " (not supertype)");
    } else {
      Symbol* name = klass_name_at(cp_index);
      log.print(" => %s", name->as_C_string());
    }
  }

  ArchiveBuilder::alloc_stats()->record_klass_cp_entry(can_archive, /*reverted=*/!can_archive);
}
#endif // INCLUDE_CDS

int ConstantPool::cp_to_object_index(int cp_index) {
  // this is harder don't do this so much.
  int i = reference_map()->find(checked_cast<u2>(cp_index));
  // We might not find the index for jsr292 call.
  return (i < 0) ? _no_index_sentinel : i;
}

void ConstantPool::string_at_put(int obj_index, oop str) {
  oop result = set_resolved_reference_at(obj_index, str);
  assert(result == nullptr || result == str, "Only set once or to the same string.");
}

void ConstantPool::trace_class_resolution(const constantPoolHandle& this_cp, Klass* k) {
  ResourceMark rm;
  int line_number = -1;
  const char * source_file = nullptr;
  if (JavaThread::current()->has_last_Java_frame()) {
    // try to identify the method which called this function.
    vframeStream vfst(JavaThread::current());
    if (!vfst.at_end()) {
      line_number = vfst.method()->line_number_from_bci(vfst.bci());
      Symbol* s = vfst.method()->method_holder()->source_file_name();
      if (s != nullptr) {
        source_file = s->as_C_string();
      }
    }
  }
  if (k != this_cp->pool_holder()) {
    // only print something if the classes are different
    if (source_file != nullptr) {
      log_debug(class, resolve)("%s %s %s:%d",
                 this_cp->pool_holder()->external_name(),
                 k->external_name(), source_file, line_number);
    } else {
      log_debug(class, resolve)("%s %s",
                 this_cp->pool_holder()->external_name(),
                 k->external_name());
    }
  }
}

Klass* ConstantPool::klass_at_impl(const constantPoolHandle& this_cp, int cp_index,
                                   TRAPS) {
  JavaThread* javaThread = THREAD;

  // A resolved constantPool entry will contain a Klass*, otherwise a Symbol*.
  // It is not safe to rely on the tag bit's here, since we don't have a lock, and
  // the entry and tag is not updated atomically.
  CPKlassSlot kslot = this_cp->klass_slot_at(cp_index);
  int resolved_klass_index = kslot.resolved_klass_index();
  int name_index = kslot.name_index();
  assert(this_cp->tag_at(name_index).is_symbol(), "sanity");

  // The tag must be JVM_CONSTANT_Class in order to read the correct value from
  // the unresolved_klasses() array.
  if (this_cp->tag_at(cp_index).is_klass()) {
    Klass* klass = this_cp->resolved_klasses()->at(resolved_klass_index);
    assert(klass != nullptr, "must be resolved");
    return klass;
  }

  // This tag doesn't change back to unresolved class unless at a safepoint.
  if (this_cp->tag_at(cp_index).is_unresolved_klass_in_error()) {
    // The original attempt to resolve this constant pool entry failed so find the
    // class of the original error and throw another error of the same class
    // (JVMS 5.4.3).
    // If there is a detail message, pass that detail message to the error.
    // The JVMS does not strictly require us to duplicate the same detail message,
    // or any internal exception fields such as cause or stacktrace.  But since the
    // detail message is often a class name or other literal string, we will repeat it
    // if we can find it in the symbol table.
    throw_resolution_error(this_cp, cp_index, CHECK_NULL);
    ShouldNotReachHere();
  }

  HandleMark hm(THREAD);
  Handle mirror_handle;
  Symbol* name = this_cp->symbol_at(name_index);
  Handle loader (THREAD, this_cp->pool_holder()->class_loader());

  Klass* k;
  {
    // Turn off the single stepping while doing class resolution
    JvmtiHideSingleStepping jhss(javaThread);
    k = SystemDictionary::resolve_or_fail(name, loader, true, THREAD);
  } //  JvmtiHideSingleStepping jhss(javaThread);

  if (!HAS_PENDING_EXCEPTION) {
    // preserve the resolved klass from unloading
    mirror_handle = Handle(THREAD, k->java_mirror());
    // Do access check for klasses
    verify_constant_pool_resolve(this_cp, k, THREAD);
  }

  // Failed to resolve class. We must record the errors so that subsequent attempts
  // to resolve this constant pool entry fail with the same error (JVMS 5.4.3).
  if (HAS_PENDING_EXCEPTION) {
    save_and_throw_exception(this_cp, cp_index, constantTag(JVM_CONSTANT_UnresolvedClass), CHECK_NULL);
    // If CHECK_NULL above doesn't return the exception, that means that
    // some other thread has beaten us and has resolved the class.
    // To preserve old behavior, we return the resolved class.
    Klass* klass = this_cp->resolved_klasses()->at(resolved_klass_index);
    assert(klass != nullptr, "must be resolved if exception was cleared");
    return klass;
  }

  // logging for class+resolve.
  if (log_is_enabled(Debug, class, resolve)){
    trace_class_resolution(this_cp, k);
  }

  // The interpreter assumes when the tag is stored, the klass is resolved
  // and the Klass* stored in _resolved_klasses is non-null, so we need
  // hardware store ordering here.
  // We also need to CAS to not overwrite an error from a racing thread.
  Klass** adr = this_cp->resolved_klasses()->adr_at(resolved_klass_index);
  Atomic::release_store(adr, k);

  jbyte old_tag = Atomic::cmpxchg((jbyte*)this_cp->tag_addr_at(cp_index),
                                  (jbyte)JVM_CONSTANT_UnresolvedClass,
                                  (jbyte)JVM_CONSTANT_Class);

  // We need to recheck exceptions from racing thread and return the same.
  if (old_tag == JVM_CONSTANT_UnresolvedClassInError) {
    // Remove klass.
    Atomic::store(adr, (Klass*)nullptr);
    throw_resolution_error(this_cp, cp_index, CHECK_NULL);
  }

  return k;
}


// Does not update ConstantPool* - to avoid any exception throwing. Used
// by compiler and exception handling.  Also used to avoid classloads for
// instanceof operations. Returns null if the class has not been loaded or
// if the verification of constant pool failed
Klass* ConstantPool::klass_at_if_loaded(const constantPoolHandle& this_cp, int which) {
  CPKlassSlot kslot = this_cp->klass_slot_at(which);
  int resolved_klass_index = kslot.resolved_klass_index();
  int name_index = kslot.name_index();
  assert(this_cp->tag_at(name_index).is_symbol(), "sanity");

  if (this_cp->tag_at(which).is_klass()) {
    Klass* k = this_cp->resolved_klasses()->at(resolved_klass_index);
    assert(k != nullptr, "must be resolved");
    return k;
  } else if (this_cp->tag_at(which).is_unresolved_klass_in_error()) {
    return nullptr;
  } else {
    Thread* current = Thread::current();
    HandleMark hm(current);
    Symbol* name = this_cp->symbol_at(name_index);
    oop loader = this_cp->pool_holder()->class_loader();
    Handle h_loader (current, loader);
    Klass* k = SystemDictionary::find_instance_klass(current, name, h_loader);

    // Avoid constant pool verification at a safepoint, as it takes the Module_lock.
    if (k != nullptr && current->is_Java_thread()) {
      // Make sure that resolving is legal
      JavaThread* THREAD = JavaThread::cast(current); // For exception macros.
      ExceptionMark em(THREAD);
      // return null if verification fails
      verify_constant_pool_resolve(this_cp, k, THREAD);
      if (HAS_PENDING_EXCEPTION) {
        CLEAR_PENDING_EXCEPTION;
        return nullptr;
      }
      return k;
    } else {
      return k;
    }
  }
}

Method* ConstantPool::method_at_if_loaded(const constantPoolHandle& cpool,
                                                   int which) {
  if (cpool->cache() == nullptr)  return nullptr;  // nothing to load yet
  if (!(which >= 0 && which < cpool->resolved_method_entries_length())) {
    // FIXME: should be an assert
    log_debug(class, resolve)("bad operand %d in:", which); cpool->print();
    return nullptr;
  }
  return cpool->cache()->method_if_resolved(which);
}


bool ConstantPool::has_appendix_at_if_loaded(const constantPoolHandle& cpool, int which, Bytecodes::Code code) {
  if (cpool->cache() == nullptr)  return false;  // nothing to load yet
  if (code == Bytecodes::_invokedynamic) {
    return cpool->resolved_indy_entry_at(which)->has_appendix();
  } else {
    return cpool->resolved_method_entry_at(which)->has_appendix();
  }
}

oop ConstantPool::appendix_at_if_loaded(const constantPoolHandle& cpool, int which, Bytecodes::Code code) {
  if (cpool->cache() == nullptr)  return nullptr;  // nothing to load yet
  if (code == Bytecodes::_invokedynamic) {
    return cpool->resolved_reference_from_indy(which);
  } else {
    return cpool->cache()->appendix_if_resolved(which);
  }
}


bool ConstantPool::has_local_signature_at_if_loaded(const constantPoolHandle& cpool, int which, Bytecodes::Code code) {
  if (cpool->cache() == nullptr)  return false;  // nothing to load yet
  if (code == Bytecodes::_invokedynamic) {
    return cpool->resolved_indy_entry_at(which)->has_local_signature();
  } else {
    return cpool->resolved_method_entry_at(which)->has_local_signature();
  }
}

// Translate index, which could be CPCache index or Indy index, to a constant pool index
int ConstantPool::to_cp_index(int index, Bytecodes::Code code) {
  assert(cache() != nullptr, "'index' is a rewritten index so this class must have been rewritten");
  switch(code) {
    case Bytecodes::_invokedynamic:
      return invokedynamic_bootstrap_ref_index_at(index);
    case Bytecodes::_getfield:
    case Bytecodes::_getstatic:
    case Bytecodes::_putfield:
    case Bytecodes::_putstatic:
      return resolved_field_entry_at(index)->constant_pool_index();
    case Bytecodes::_invokeinterface:
    case Bytecodes::_invokehandle:
    case Bytecodes::_invokespecial:
    case Bytecodes::_invokestatic:
    case Bytecodes::_invokevirtual:
    case Bytecodes::_fast_invokevfinal: // Bytecode interpreter uses this
      return resolved_method_entry_at(index)->constant_pool_index();
    default:
      fatal("Unexpected bytecode: %s", Bytecodes::name(code));
  }
}

bool ConstantPool::is_resolved(int index, Bytecodes::Code code) {
  assert(cache() != nullptr, "'index' is a rewritten index so this class must have been rewritten");
  switch(code) {
    case Bytecodes::_invokedynamic:
      return resolved_indy_entry_at(index)->is_resolved();

    case Bytecodes::_getfield:
    case Bytecodes::_getstatic:
    case Bytecodes::_putfield:
    case Bytecodes::_putstatic:
      return resolved_field_entry_at(index)->is_resolved(code);

    case Bytecodes::_invokeinterface:
    case Bytecodes::_invokehandle:
    case Bytecodes::_invokespecial:
    case Bytecodes::_invokestatic:
    case Bytecodes::_invokevirtual:
    case Bytecodes::_fast_invokevfinal: // Bytecode interpreter uses this
      return resolved_method_entry_at(index)->is_resolved(code);

    default:
      fatal("Unexpected bytecode: %s", Bytecodes::name(code));
  }
}

u2 ConstantPool::uncached_name_and_type_ref_index_at(int cp_index)  {
  if (tag_at(cp_index).has_bootstrap()) {
    u2 pool_index = bootstrap_name_and_type_ref_index_at(cp_index);
    assert(tag_at(pool_index).is_name_and_type(), "");
    return pool_index;
  }
  assert(tag_at(cp_index).is_field_or_method(), "Corrupted constant pool");
  assert(!tag_at(cp_index).has_bootstrap(), "Must be handled above");
  jint ref_index = *int_at_addr(cp_index);
  return extract_high_short_from_int(ref_index);
}

u2 ConstantPool::name_and_type_ref_index_at(int index, Bytecodes::Code code) {
  return uncached_name_and_type_ref_index_at(to_cp_index(index, code));
}

constantTag ConstantPool::tag_ref_at(int which, Bytecodes::Code code) {
  // which may be either a Constant Pool index or a rewritten index
  int pool_index = which;
  assert(cache() != nullptr, "'index' is a rewritten index so this class must have been rewritten");
  pool_index = to_cp_index(which, code);
  return tag_at(pool_index);
}

u2 ConstantPool::uncached_klass_ref_index_at(int cp_index) {
  assert(tag_at(cp_index).is_field_or_method(), "Corrupted constant pool");
  jint ref_index = *int_at_addr(cp_index);
  return extract_low_short_from_int(ref_index);
}

u2 ConstantPool::klass_ref_index_at(int index, Bytecodes::Code code) {
  assert(code != Bytecodes::_invokedynamic,
            "an invokedynamic instruction does not have a klass");
  return uncached_klass_ref_index_at(to_cp_index(index, code));
}

void ConstantPool::verify_constant_pool_resolve(const constantPoolHandle& this_cp, Klass* k, TRAPS) {
  if (!(k->is_instance_klass() || k->is_objArray_klass())) {
    return;  // short cut, typeArray klass is always accessible
  }
  Klass* holder = this_cp->pool_holder();
  LinkResolver::check_klass_accessibility(holder, k, CHECK);
}


u2 ConstantPool::name_ref_index_at(int cp_index) {
  jint ref_index = name_and_type_at(cp_index);
  return extract_low_short_from_int(ref_index);
}


u2 ConstantPool::signature_ref_index_at(int cp_index) {
  jint ref_index = name_and_type_at(cp_index);
  return extract_high_short_from_int(ref_index);
}


Klass* ConstantPool::klass_ref_at(int which, Bytecodes::Code code, TRAPS) {
  return klass_at(klass_ref_index_at(which, code), THREAD);
}

Symbol* ConstantPool::klass_name_at(int cp_index) const {
  return symbol_at(klass_slot_at(cp_index).name_index());
}

Symbol* ConstantPool::klass_ref_at_noresolve(int which, Bytecodes::Code code) {
  jint ref_index = klass_ref_index_at(which, code);
  return klass_at_noresolve(ref_index);
}

Symbol* ConstantPool::uncached_klass_ref_at_noresolve(int cp_index) {
  jint ref_index = uncached_klass_ref_index_at(cp_index);
  return klass_at_noresolve(ref_index);
}

char* ConstantPool::string_at_noresolve(int cp_index) {
  return unresolved_string_at(cp_index)->as_C_string();
}

BasicType ConstantPool::basic_type_for_signature_at(int cp_index) const {
  return Signature::basic_type(symbol_at(cp_index));
}


void ConstantPool::resolve_string_constants_impl(const constantPoolHandle& this_cp, TRAPS) {
  for (int index = 1; index < this_cp->length(); index++) { // Index 0 is unused
    if (this_cp->tag_at(index).is_string()) {
      this_cp->string_at(index, CHECK);
    }
  }
}

static const char* exception_message(const constantPoolHandle& this_cp, int which, constantTag tag, oop pending_exception) {
  // Note: caller needs ResourceMark

  // Dig out the detailed message to reuse if possible
  const char* msg = java_lang_Throwable::message_as_utf8(pending_exception);
  if (msg != nullptr) {
    return msg;
  }

  Symbol* message = nullptr;
  // Return specific message for the tag
  switch (tag.value()) {
  case JVM_CONSTANT_UnresolvedClass:
    // return the class name in the error message
    message = this_cp->klass_name_at(which);
    break;
  case JVM_CONSTANT_MethodHandle:
    // return the method handle name in the error message
    message = this_cp->method_handle_name_ref_at(which);
    break;
  case JVM_CONSTANT_MethodType:
    // return the method type signature in the error message
    message = this_cp->method_type_signature_at(which);
    break;
  case JVM_CONSTANT_Dynamic:
    // return the name of the condy in the error message
    message = this_cp->uncached_name_ref_at(which);
    break;
  default:
    ShouldNotReachHere();
  }

  return message != nullptr ? message->as_C_string() : nullptr;
}

static void add_resolution_error(JavaThread* current, const constantPoolHandle& this_cp, int which,
                                 constantTag tag, oop pending_exception) {

  ResourceMark rm(current);
  Symbol* error = pending_exception->klass()->name();
  oop cause = java_lang_Throwable::cause(pending_exception);

  // Also dig out the exception cause, if present.
  Symbol* cause_sym = nullptr;
  const char* cause_msg = nullptr;
  if (cause != nullptr && cause != pending_exception) {
    cause_sym = cause->klass()->name();
    cause_msg = java_lang_Throwable::message_as_utf8(cause);
  }

  const char* message = exception_message(this_cp, which, tag, pending_exception);
  SystemDictionary::add_resolution_error(this_cp, which, error, message, cause_sym, cause_msg);
}


void ConstantPool::throw_resolution_error(const constantPoolHandle& this_cp, int which, TRAPS) {
  ResourceMark rm(THREAD);
  const char* message = nullptr;
  Symbol* cause = nullptr;
  const char* cause_msg = nullptr;
  Symbol* error = SystemDictionary::find_resolution_error(this_cp, which, &message, &cause, &cause_msg);
  assert(error != nullptr, "checking");

  CLEAR_PENDING_EXCEPTION;
  if (message != nullptr) {
    if (cause != nullptr) {
      Handle h_cause = Exceptions::new_exception(THREAD, cause, cause_msg);
      THROW_MSG_CAUSE(error, message, h_cause);
    } else {
      THROW_MSG(error, message);
    }
  } else {
    if (cause != nullptr) {
      Handle h_cause = Exceptions::new_exception(THREAD, cause, cause_msg);
      THROW_CAUSE(error, h_cause);
    } else {
      THROW(error);
    }
  }
}

// If resolution for Class, Dynamic constant, MethodHandle or MethodType fails, save the
// exception in the resolution error table, so that the same exception is thrown again.
void ConstantPool::save_and_throw_exception(const constantPoolHandle& this_cp, int cp_index,
                                            constantTag tag, TRAPS) {

  int error_tag = tag.error_value();

  if (!PENDING_EXCEPTION->
    is_a(vmClasses::LinkageError_klass())) {
    // Just throw the exception and don't prevent these classes from
    // being loaded due to virtual machine errors like StackOverflow
    // and OutOfMemoryError, etc, or if the thread was hit by stop()
    // Needs clarification to section 5.4.3 of the VM spec (see 6308271)
  } else if (this_cp->tag_at(cp_index).value() != error_tag) {
    add_resolution_error(THREAD, this_cp, cp_index, tag, PENDING_EXCEPTION);
    // CAS in the tag.  If a thread beat us to registering this error that's fine.
    // If another thread resolved the reference, this is a race condition. This
    // thread may have had a security manager or something temporary.
    // This doesn't deterministically get an error.   So why do we save this?
    // We save this because jvmti can add classes to the bootclass path after
    // this error, so it needs to get the same error if the error is first.
    jbyte old_tag = Atomic::cmpxchg((jbyte*)this_cp->tag_addr_at(cp_index),
                                    (jbyte)tag.value(),
                                    (jbyte)error_tag);
    if (old_tag != error_tag && old_tag != tag.value()) {
      // MethodHandles and MethodType doesn't change to resolved version.
      assert(this_cp->tag_at(cp_index).is_klass(), "Wrong tag value");
      // Forget the exception and use the resolved class.
      CLEAR_PENDING_EXCEPTION;
    }
  } else {
    // some other thread put this in error state
    throw_resolution_error(this_cp, cp_index, CHECK);
  }
}

constantTag ConstantPool::constant_tag_at(int cp_index) {
  constantTag tag = tag_at(cp_index);
  if (tag.is_dynamic_constant()) {
    BasicType bt = basic_type_for_constant_at(cp_index);
    return constantTag(constantTag::type2tag(bt));
  }
  return tag;
}

BasicType ConstantPool::basic_type_for_constant_at(int cp_index) {
  constantTag tag = tag_at(cp_index);
  if (tag.is_dynamic_constant() ||
      tag.is_dynamic_constant_in_error()) {
    // have to look at the signature for this one
    Symbol* constant_type = uncached_signature_ref_at(cp_index);
    return Signature::basic_type(constant_type);
  }
  return tag.basic_type();
}

// Called to resolve constants in the constant pool and return an oop.
// Some constant pool entries cache their resolved oop. This is also
// called to create oops from constants to use in arguments for invokedynamic
oop ConstantPool::resolve_constant_at_impl(const constantPoolHandle& this_cp,
                                           int cp_index, int cache_index,
                                           bool* status_return, TRAPS) {
  oop result_oop = nullptr;

  if (cache_index == _possible_index_sentinel) {
    // It is possible that this constant is one which is cached in the objects.
    // We'll do a linear search.  This should be OK because this usage is rare.
    // FIXME: If bootstrap specifiers stress this code, consider putting in
    // a reverse index.  Binary search over a short array should do it.
    assert(cp_index > 0, "valid constant pool index");
    cache_index = this_cp->cp_to_object_index(cp_index);
  }
  assert(cache_index == _no_index_sentinel || cache_index >= 0, "");
  assert(cp_index == _no_index_sentinel || cp_index >= 0, "");

  if (cache_index >= 0) {
    result_oop = this_cp->resolved_reference_at(cache_index);
    if (result_oop != nullptr) {
      if (result_oop == Universe::the_null_sentinel()) {
        DEBUG_ONLY(int temp_index = (cp_index >= 0 ? cp_index : this_cp->object_to_cp_index(cache_index)));
        assert(this_cp->tag_at(temp_index).is_dynamic_constant(), "only condy uses the null sentinel");
        result_oop = nullptr;
      }
      if (status_return != nullptr)  (*status_return) = true;
      return result_oop;
      // That was easy...
    }
    cp_index = this_cp->object_to_cp_index(cache_index);
  }

  jvalue prim_value;  // temp used only in a few cases below

  constantTag tag = this_cp->tag_at(cp_index);

  if (status_return != nullptr) {
    // don't trigger resolution if the constant might need it
    switch (tag.value()) {
    case JVM_CONSTANT_Class:
      assert(this_cp->resolved_klass_at(cp_index) != nullptr, "must be resolved");
      break;
    case JVM_CONSTANT_String:
    case JVM_CONSTANT_Integer:
    case JVM_CONSTANT_Float:
    case JVM_CONSTANT_Long:
    case JVM_CONSTANT_Double:
      // these guys trigger OOM at worst
      break;
    default:
      (*status_return) = false;
      return nullptr;
    }
    // from now on there is either success or an OOME
    (*status_return) = true;
  }

  switch (tag.value()) {

  case JVM_CONSTANT_UnresolvedClass:
  case JVM_CONSTANT_Class:
    {
      assert(cache_index == _no_index_sentinel, "should not have been set");
      Klass* resolved = klass_at_impl(this_cp, cp_index, CHECK_NULL);
      // ldc wants the java mirror.
      result_oop = resolved->java_mirror();
      break;
    }

  case JVM_CONSTANT_Dynamic:
    { PerfTraceTimedEvent timer(ClassLoader::perf_resolve_invokedynamic_time(),
                                ClassLoader::perf_resolve_invokedynamic_count());

      // Resolve the Dynamically-Computed constant to invoke the BSM in order to obtain the resulting oop.
      BootstrapInfo bootstrap_specifier(this_cp, cp_index);

      // The initial step in resolving an unresolved symbolic reference to a
      // dynamically-computed constant is to resolve the symbolic reference to a
      // method handle which will be the bootstrap method for the dynamically-computed
      // constant. If resolution of the java.lang.invoke.MethodHandle for the bootstrap
      // method fails, then a MethodHandleInError is stored at the corresponding
      // bootstrap method's CP index for the CONSTANT_MethodHandle_info. No need to
      // set a DynamicConstantInError here since any subsequent use of this
      // bootstrap method will encounter the resolution of MethodHandleInError.
      // Both the first, (resolution of the BSM and its static arguments), and the second tasks,
      // (invocation of the BSM), of JVMS Section 5.4.3.6 occur within invoke_bootstrap_method()
      // for the bootstrap_specifier created above.
      SystemDictionary::invoke_bootstrap_method(bootstrap_specifier, THREAD);
      Exceptions::wrap_dynamic_exception(/* is_indy */ false, THREAD);
      if (HAS_PENDING_EXCEPTION) {
        // Resolution failure of the dynamically-computed constant, save_and_throw_exception
        // will check for a LinkageError and store a DynamicConstantInError.
        save_and_throw_exception(this_cp, cp_index, tag, CHECK_NULL);
      }
      result_oop = bootstrap_specifier.resolved_value()();
      BasicType type = Signature::basic_type(bootstrap_specifier.signature());
      if (!is_reference_type(type)) {
        // Make sure the primitive value is properly boxed.
        // This is a JDK responsibility.
        const char* fail = nullptr;
        if (result_oop == nullptr) {
          fail = "null result instead of box";
        } else if (!is_java_primitive(type)) {
          // FIXME: support value types via unboxing
          fail = "can only handle references and primitives";
        } else if (!java_lang_boxing_object::is_instance(result_oop, type)) {
          fail = "primitive is not properly boxed";
        }
        if (fail != nullptr) {
          // Since this exception is not a LinkageError, throw exception
          // but do not save a DynamicInError resolution result.
          // See section 5.4.3 of the VM spec.
          THROW_MSG_NULL(vmSymbols::java_lang_InternalError(), fail);
        }
      }

      LogTarget(Debug, methodhandles, condy) lt_condy;
      if (lt_condy.is_enabled()) {
        LogStream ls(lt_condy);
        bootstrap_specifier.print_msg_on(&ls, "resolve_constant_at_impl");
      }
      break;
    }

  case JVM_CONSTANT_String:
    assert(cache_index != _no_index_sentinel, "should have been set");
    result_oop = string_at_impl(this_cp, cp_index, cache_index, CHECK_NULL);
    break;

  case JVM_CONSTANT_MethodHandle:
    { PerfTraceTimedEvent timer(ClassLoader::perf_resolve_method_handle_time(),
                                ClassLoader::perf_resolve_method_handle_count());

      int ref_kind                 = this_cp->method_handle_ref_kind_at(cp_index);
      int callee_index             = this_cp->method_handle_klass_index_at(cp_index);
      Symbol*  name =      this_cp->method_handle_name_ref_at(cp_index);
      Symbol*  signature = this_cp->method_handle_signature_ref_at(cp_index);
      constantTag m_tag  = this_cp->tag_at(this_cp->method_handle_index_at(cp_index));
      { ResourceMark rm(THREAD);
        log_debug(class, resolve)("resolve JVM_CONSTANT_MethodHandle:%d [%d/%d/%d] %s.%s",
                              ref_kind, cp_index, this_cp->method_handle_index_at(cp_index),
                              callee_index, name->as_C_string(), signature->as_C_string());
      }

      Klass* callee = klass_at_impl(this_cp, callee_index, THREAD);
      if (HAS_PENDING_EXCEPTION) {
        save_and_throw_exception(this_cp, cp_index, tag, CHECK_NULL);
      }

      // Check constant pool method consistency
      if ((callee->is_interface() && m_tag.is_method()) ||
          (!callee->is_interface() && m_tag.is_interface_method())) {
        ResourceMark rm(THREAD);
        stringStream ss;
        ss.print("Inconsistent constant pool data in classfile for class %s. "
                 "Method '", callee->name()->as_C_string());
        signature->print_as_signature_external_return_type(&ss);
        ss.print(" %s(", name->as_C_string());
        signature->print_as_signature_external_parameters(&ss);
        ss.print(")' at index %d is %s and should be %s",
                 cp_index,
                 callee->is_interface() ? "CONSTANT_MethodRef" : "CONSTANT_InterfaceMethodRef",
                 callee->is_interface() ? "CONSTANT_InterfaceMethodRef" : "CONSTANT_MethodRef");
        // Names are all known to be < 64k so we know this formatted message is not excessively large.
        Exceptions::fthrow(THREAD_AND_LOCATION, vmSymbols::java_lang_IncompatibleClassChangeError(), "%s", ss.as_string());
        save_and_throw_exception(this_cp, cp_index, tag, CHECK_NULL);
      }

      Klass* klass = this_cp->pool_holder();
      HandleMark hm(THREAD);
      Handle value = SystemDictionary::link_method_handle_constant(klass, ref_kind,
                                                                   callee, name, signature,
                                                                   THREAD);
      if (HAS_PENDING_EXCEPTION) {
        save_and_throw_exception(this_cp, cp_index, tag, CHECK_NULL);
      }
      result_oop = value();
      break;
    }

  case JVM_CONSTANT_MethodType:
    { PerfTraceTimedEvent timer(ClassLoader::perf_resolve_method_type_time(),
                                ClassLoader::perf_resolve_method_type_count());

      Symbol*  signature = this_cp->method_type_signature_at(cp_index);
      { ResourceMark rm(THREAD);
        log_debug(class, resolve)("resolve JVM_CONSTANT_MethodType [%d/%d] %s",
                              cp_index, this_cp->method_type_index_at(cp_index),
                              signature->as_C_string());
      }
      Klass* klass = this_cp->pool_holder();
      HandleMark hm(THREAD);
      Handle value = SystemDictionary::find_method_handle_type(signature, klass, THREAD);
      result_oop = value();
      if (HAS_PENDING_EXCEPTION) {
        save_and_throw_exception(this_cp, cp_index, tag, CHECK_NULL);
      }
      break;
    }

  case JVM_CONSTANT_Integer:
    assert(cache_index == _no_index_sentinel, "should not have been set");
    prim_value.i = this_cp->int_at(cp_index);
    result_oop = java_lang_boxing_object::create(T_INT, &prim_value, CHECK_NULL);
    break;

  case JVM_CONSTANT_Float:
    assert(cache_index == _no_index_sentinel, "should not have been set");
    prim_value.f = this_cp->float_at(cp_index);
    result_oop = java_lang_boxing_object::create(T_FLOAT, &prim_value, CHECK_NULL);
    break;

  case JVM_CONSTANT_Long:
    assert(cache_index == _no_index_sentinel, "should not have been set");
    prim_value.j = this_cp->long_at(cp_index);
    result_oop = java_lang_boxing_object::create(T_LONG, &prim_value, CHECK_NULL);
    break;

  case JVM_CONSTANT_Double:
    assert(cache_index == _no_index_sentinel, "should not have been set");
    prim_value.d = this_cp->double_at(cp_index);
    result_oop = java_lang_boxing_object::create(T_DOUBLE, &prim_value, CHECK_NULL);
    break;

  case JVM_CONSTANT_UnresolvedClassInError:
  case JVM_CONSTANT_DynamicInError:
  case JVM_CONSTANT_MethodHandleInError:
  case JVM_CONSTANT_MethodTypeInError:
    throw_resolution_error(this_cp, cp_index, CHECK_NULL);
    break;

  default:
    fatal("unexpected constant tag at CP %p[%d/%d] = %d", this_cp(), cp_index, cache_index, tag.value());
    break;
  }

  if (cache_index >= 0) {
    // Benign race condition:  resolved_references may already be filled in.
    // The important thing here is that all threads pick up the same result.
    // It doesn't matter which racing thread wins, as long as only one
    // result is used by all threads, and all future queries.
    oop new_result = (result_oop == nullptr ? Universe::the_null_sentinel() : result_oop);
    oop old_result = this_cp->set_resolved_reference_at(cache_index, new_result);
    if (old_result == nullptr) {
      return result_oop;  // was installed
    } else {
      // Return the winning thread's result.  This can be different than
      // the result here for MethodHandles.
      if (old_result == Universe::the_null_sentinel())
        old_result = nullptr;
      return old_result;
    }
  } else {
    assert(result_oop != Universe::the_null_sentinel(), "");
    return result_oop;
  }
}

oop ConstantPool::uncached_string_at(int cp_index, TRAPS) {
  Symbol* sym = unresolved_string_at(cp_index);
  oop str = StringTable::intern(sym, CHECK_(nullptr));
  assert(java_lang_String::is_instance(str), "must be string");
  return str;
}

void ConstantPool::copy_bootstrap_arguments_at_impl(const constantPoolHandle& this_cp, int cp_index,
                                                    int start_arg, int end_arg,
                                                    objArrayHandle info, int pos,
                                                    bool must_resolve, Handle if_not_available,
                                                    TRAPS) {
  int limit = pos + end_arg - start_arg;
  // checks: cp_index in range [0..this_cp->length),
  // tag at cp_index, start..end in range [0..this_cp->bootstrap_argument_count],
  // info array non-null, pos..limit in [0..info.length]
  if ((0 >= cp_index    || cp_index >= this_cp->length())  ||
      !(this_cp->tag_at(cp_index).is_invoke_dynamic()    ||
        this_cp->tag_at(cp_index).is_dynamic_constant()) ||
      (0 > start_arg || start_arg > end_arg) ||
      (end_arg > this_cp->bootstrap_argument_count_at(cp_index)) ||
      (0 > pos       || pos > limit)         ||
      (info.is_null() || limit > info->length())) {
    // An index or something else went wrong; throw an error.
    // Since this is an internal API, we don't expect this,
    // so we don't bother to craft a nice message.
    THROW_MSG(vmSymbols::java_lang_LinkageError(), "bad BSM argument access");
  }
  // now we can loop safely
  int info_i = pos;
  for (int i = start_arg; i < end_arg; i++) {
    int arg_index = this_cp->bootstrap_argument_index_at(cp_index, i);
    oop arg_oop;
    if (must_resolve) {
      arg_oop = this_cp->resolve_possibly_cached_constant_at(arg_index, CHECK);
    } else {
      bool found_it = false;
      arg_oop = this_cp->find_cached_constant_at(arg_index, found_it, CHECK);
      if (!found_it)  arg_oop = if_not_available();
    }
    info->obj_at_put(info_i++, arg_oop);
  }
}

oop ConstantPool::string_at_impl(const constantPoolHandle& this_cp, int cp_index, int obj_index, TRAPS) {
  // If the string has already been interned, this entry will be non-null
  oop str = this_cp->resolved_reference_at(obj_index);
  assert(str != Universe::the_null_sentinel(), "");
  if (str != nullptr) return str;
  Symbol* sym = this_cp->unresolved_string_at(cp_index);
  str = StringTable::intern(sym, CHECK_(nullptr));
  this_cp->string_at_put(obj_index, str);
  assert(java_lang_String::is_instance(str), "must be string");
  return str;
}


bool ConstantPool::klass_name_at_matches(const InstanceKlass* k, int cp_index) {
  // Names are interned, so we can compare Symbol*s directly
  Symbol* cp_name = klass_name_at(cp_index);
  return (cp_name == k->name());
}


// Iterate over symbols and decrement ones which are Symbol*s
// This is done during GC.
// Only decrement the UTF8 symbols. Strings point to
// these symbols but didn't increment the reference count.
void ConstantPool::unreference_symbols() {
  for (int index = 1; index < length(); index++) { // Index 0 is unused
    constantTag tag = tag_at(index);
    if (tag.is_symbol()) {
      symbol_at(index)->decrement_refcount();
    }
  }
}


// Compare this constant pool's entry at index1 to the constant pool
// cp2's entry at index2.
bool ConstantPool::compare_entry_to(int index1, const constantPoolHandle& cp2,
       int index2) {

  // The error tags are equivalent to non-error tags when comparing
  jbyte t1 = tag_at(index1).non_error_value();
  jbyte t2 = cp2->tag_at(index2).non_error_value();

  // Some classes are pre-resolved (like Throwable) which may lead to
  // consider it as a different entry. We then revert them back temporarily
  // to ensure proper comparison.
  if (t1 == JVM_CONSTANT_Class) {
    t1 = JVM_CONSTANT_UnresolvedClass;
  }
  if (t2 == JVM_CONSTANT_Class) {
    t2 = JVM_CONSTANT_UnresolvedClass;
  }

  if (t1 != t2) {
    // Not the same entry type so there is nothing else to check. Note
    // that this style of checking will consider resolved/unresolved
    // class pairs as different.
    // From the ConstantPool* API point of view, this is correct
    // behavior. See VM_RedefineClasses::merge_constant_pools() to see how this
    // plays out in the context of ConstantPool* merging.
    return false;
  }

  switch (t1) {
  case JVM_CONSTANT_ClassIndex:
  {
    int recur1 = klass_index_at(index1);
    int recur2 = cp2->klass_index_at(index2);
    if (compare_entry_to(recur1, cp2, recur2)) {
      return true;
    }
  } break;

  case JVM_CONSTANT_Double:
  {
    jdouble d1 = double_at(index1);
    jdouble d2 = cp2->double_at(index2);
    if (d1 == d2) {
      return true;
    }
  } break;

  case JVM_CONSTANT_Fieldref:
  case JVM_CONSTANT_InterfaceMethodref:
  case JVM_CONSTANT_Methodref:
  {
    int recur1 = uncached_klass_ref_index_at(index1);
    int recur2 = cp2->uncached_klass_ref_index_at(index2);
    bool match = compare_entry_to(recur1, cp2, recur2);
    if (match) {
      recur1 = uncached_name_and_type_ref_index_at(index1);
      recur2 = cp2->uncached_name_and_type_ref_index_at(index2);
      if (compare_entry_to(recur1, cp2, recur2)) {
        return true;
      }
    }
  } break;

  case JVM_CONSTANT_Float:
  {
    jfloat f1 = float_at(index1);
    jfloat f2 = cp2->float_at(index2);
    if (f1 == f2) {
      return true;
    }
  } break;

  case JVM_CONSTANT_Integer:
  {
    jint i1 = int_at(index1);
    jint i2 = cp2->int_at(index2);
    if (i1 == i2) {
      return true;
    }
  } break;

  case JVM_CONSTANT_Long:
  {
    jlong l1 = long_at(index1);
    jlong l2 = cp2->long_at(index2);
    if (l1 == l2) {
      return true;
    }
  } break;

  case JVM_CONSTANT_NameAndType:
  {
    int recur1 = name_ref_index_at(index1);
    int recur2 = cp2->name_ref_index_at(index2);
    if (compare_entry_to(recur1, cp2, recur2)) {
      recur1 = signature_ref_index_at(index1);
      recur2 = cp2->signature_ref_index_at(index2);
      if (compare_entry_to(recur1, cp2, recur2)) {
        return true;
      }
    }
  } break;

  case JVM_CONSTANT_StringIndex:
  {
    int recur1 = string_index_at(index1);
    int recur2 = cp2->string_index_at(index2);
    if (compare_entry_to(recur1, cp2, recur2)) {
      return true;
    }
  } break;

  case JVM_CONSTANT_UnresolvedClass:
  {
    Symbol* k1 = klass_name_at(index1);
    Symbol* k2 = cp2->klass_name_at(index2);
    if (k1 == k2) {
      return true;
    }
  } break;

  case JVM_CONSTANT_MethodType:
  {
    int k1 = method_type_index_at(index1);
    int k2 = cp2->method_type_index_at(index2);
    if (compare_entry_to(k1, cp2, k2)) {
      return true;
    }
  } break;

  case JVM_CONSTANT_MethodHandle:
  {
    int k1 = method_handle_ref_kind_at(index1);
    int k2 = cp2->method_handle_ref_kind_at(index2);
    if (k1 == k2) {
      int i1 = method_handle_index_at(index1);
      int i2 = cp2->method_handle_index_at(index2);
      if (compare_entry_to(i1, cp2, i2)) {
        return true;
      }
    }
  } break;

  case JVM_CONSTANT_Dynamic:
  {
    int k1 = bootstrap_name_and_type_ref_index_at(index1);
    int k2 = cp2->bootstrap_name_and_type_ref_index_at(index2);
    int i1 = bootstrap_methods_attribute_index(index1);
    int i2 = cp2->bootstrap_methods_attribute_index(index2);
    bool match_entry = compare_entry_to(k1, cp2, k2);
    bool match_operand = compare_operand_to(i1, cp2, i2);
    return (match_entry && match_operand);
  } break;

  case JVM_CONSTANT_InvokeDynamic:
  {
    int k1 = bootstrap_name_and_type_ref_index_at(index1);
    int k2 = cp2->bootstrap_name_and_type_ref_index_at(index2);
    int i1 = bootstrap_methods_attribute_index(index1);
    int i2 = cp2->bootstrap_methods_attribute_index(index2);
    bool match_entry = compare_entry_to(k1, cp2, k2);
    bool match_operand = compare_operand_to(i1, cp2, i2);
    return (match_entry && match_operand);
  } break;

  case JVM_CONSTANT_String:
  {
    Symbol* s1 = unresolved_string_at(index1);
    Symbol* s2 = cp2->unresolved_string_at(index2);
    if (s1 == s2) {
      return true;
    }
  } break;

  case JVM_CONSTANT_Utf8:
  {
    Symbol* s1 = symbol_at(index1);
    Symbol* s2 = cp2->symbol_at(index2);
    if (s1 == s2) {
      return true;
    }
  } break;

  // Invalid is used as the tag for the second constant pool entry
  // occupied by JVM_CONSTANT_Double or JVM_CONSTANT_Long. It should
  // not be seen by itself.
  case JVM_CONSTANT_Invalid: // fall through

  default:
    ShouldNotReachHere();
    break;
  }

  return false;
} // end compare_entry_to()


// Resize the operands array with delta_len and delta_size.
// Used in RedefineClasses for CP merge.
void ConstantPool::resize_operands(int delta_len, int delta_size, TRAPS) {
  int old_len  = operand_array_length(operands());
  int new_len  = old_len + delta_len;
  int min_len  = (delta_len > 0) ? old_len : new_len;

  int old_size = operands()->length();
  int new_size = old_size + delta_size;
  int min_size = (delta_size > 0) ? old_size : new_size;

  ClassLoaderData* loader_data = pool_holder()->class_loader_data();
  Array<u2>* new_ops = MetadataFactory::new_array<u2>(loader_data, new_size, CHECK);

  // Set index in the resized array for existing elements only
  for (int idx = 0; idx < min_len; idx++) {
    int offset = operand_offset_at(idx);                       // offset in original array
    operand_offset_at_put(new_ops, idx, offset + 2*delta_len); // offset in resized array
  }
  // Copy the bootstrap specifiers only
  Copy::conjoint_memory_atomic(operands()->adr_at(2*old_len),
                               new_ops->adr_at(2*new_len),
                               (min_size - 2*min_len) * sizeof(u2));
  // Explicitly deallocate old operands array.
  // Note, it is not needed for 7u backport.
  if ( operands() != nullptr) { // the safety check
    MetadataFactory::free_array<u2>(loader_data, operands());
  }
  set_operands(new_ops);
} // end resize_operands()


// Extend the operands array with the length and size of the ext_cp operands.
// Used in RedefineClasses for CP merge.
void ConstantPool::extend_operands(const constantPoolHandle& ext_cp, TRAPS) {
  int delta_len = operand_array_length(ext_cp->operands());
  if (delta_len == 0) {
    return; // nothing to do
  }
  int delta_size = ext_cp->operands()->length();

  assert(delta_len  > 0 && delta_size > 0, "extended operands array must be bigger");

  if (operand_array_length(operands()) == 0) {
    ClassLoaderData* loader_data = pool_holder()->class_loader_data();
    Array<u2>* new_ops = MetadataFactory::new_array<u2>(loader_data, delta_size, CHECK);
    // The first element index defines the offset of second part
    operand_offset_at_put(new_ops, 0, 2*delta_len); // offset in new array
    set_operands(new_ops);
  } else {
    resize_operands(delta_len, delta_size, CHECK);
  }

} // end extend_operands()


// Shrink the operands array to a smaller array with new_len length.
// Used in RedefineClasses for CP merge.
void ConstantPool::shrink_operands(int new_len, TRAPS) {
  int old_len = operand_array_length(operands());
  if (new_len == old_len) {
    return; // nothing to do
  }
  assert(new_len < old_len, "shrunken operands array must be smaller");

  int free_base  = operand_next_offset_at(new_len - 1);
  int delta_len  = new_len - old_len;
  int delta_size = 2*delta_len + free_base - operands()->length();

  resize_operands(delta_len, delta_size, CHECK);

} // end shrink_operands()


void ConstantPool::copy_operands(const constantPoolHandle& from_cp,
                                 const constantPoolHandle& to_cp,
                                 TRAPS) {

  int from_oplen = operand_array_length(from_cp->operands());
  int old_oplen  = operand_array_length(to_cp->operands());
  if (from_oplen != 0) {
    ClassLoaderData* loader_data = to_cp->pool_holder()->class_loader_data();
    // append my operands to the target's operands array
    if (old_oplen == 0) {
      // Can't just reuse from_cp's operand list because of deallocation issues
      int len = from_cp->operands()->length();
      Array<u2>* new_ops = MetadataFactory::new_array<u2>(loader_data, len, CHECK);
      Copy::conjoint_memory_atomic(
          from_cp->operands()->adr_at(0), new_ops->adr_at(0), len * sizeof(u2));
      to_cp->set_operands(new_ops);
    } else {
      int old_len  = to_cp->operands()->length();
      int from_len = from_cp->operands()->length();
      int old_off  = old_oplen * sizeof(u2);
      int from_off = from_oplen * sizeof(u2);
      // Use the metaspace for the destination constant pool
      Array<u2>* new_operands = MetadataFactory::new_array<u2>(loader_data, old_len + from_len, CHECK);
      int fillp = 0, len = 0;
      // first part of dest
      Copy::conjoint_memory_atomic(to_cp->operands()->adr_at(0),
                                   new_operands->adr_at(fillp),
                                   (len = old_off) * sizeof(u2));
      fillp += len;
      // first part of src
      Copy::conjoint_memory_atomic(from_cp->operands()->adr_at(0),
                                   new_operands->adr_at(fillp),
                                   (len = from_off) * sizeof(u2));
      fillp += len;
      // second part of dest
      Copy::conjoint_memory_atomic(to_cp->operands()->adr_at(old_off),
                                   new_operands->adr_at(fillp),
                                   (len = old_len - old_off) * sizeof(u2));
      fillp += len;
      // second part of src
      Copy::conjoint_memory_atomic(from_cp->operands()->adr_at(from_off),
                                   new_operands->adr_at(fillp),
                                   (len = from_len - from_off) * sizeof(u2));
      fillp += len;
      assert(fillp == new_operands->length(), "");

      // Adjust indexes in the first part of the copied operands array.
      for (int j = 0; j < from_oplen; j++) {
        int offset = operand_offset_at(new_operands, old_oplen + j);
        assert(offset == operand_offset_at(from_cp->operands(), j), "correct copy");
        offset += old_len;  // every new tuple is preceded by old_len extra u2's
        operand_offset_at_put(new_operands, old_oplen + j, offset);
      }

      // replace target operands array with combined array
      to_cp->set_operands(new_operands);
    }
  }
} // end copy_operands()


// Copy this constant pool's entries at start_i to end_i (inclusive)
// to the constant pool to_cp's entries starting at to_i. A total of
// (end_i - start_i) + 1 entries are copied.
void ConstantPool::copy_cp_to_impl(const constantPoolHandle& from_cp, int start_i, int end_i,
       const constantPoolHandle& to_cp, int to_i, TRAPS) {


  int dest_cpi = to_i;  // leave original alone for debug purposes

  for (int src_cpi = start_i; src_cpi <= end_i; /* see loop bottom */ ) {
    copy_entry_to(from_cp, src_cpi, to_cp, dest_cpi);

    switch (from_cp->tag_at(src_cpi).value()) {
    case JVM_CONSTANT_Double:
    case JVM_CONSTANT_Long:
      // double and long take two constant pool entries
      src_cpi += 2;
      dest_cpi += 2;
      break;

    default:
      // all others take one constant pool entry
      src_cpi++;
      dest_cpi++;
      break;
    }
  }
  copy_operands(from_cp, to_cp, CHECK);

} // end copy_cp_to_impl()


// Copy this constant pool's entry at from_i to the constant pool
// to_cp's entry at to_i.
void ConstantPool::copy_entry_to(const constantPoolHandle& from_cp, int from_i,
                                        const constantPoolHandle& to_cp, int to_i) {

  int tag = from_cp->tag_at(from_i).value();
  switch (tag) {
  case JVM_CONSTANT_ClassIndex:
  {
    jint ki = from_cp->klass_index_at(from_i);
    to_cp->klass_index_at_put(to_i, ki);
  } break;

  case JVM_CONSTANT_Double:
  {
    jdouble d = from_cp->double_at(from_i);
    to_cp->double_at_put(to_i, d);
    // double takes two constant pool entries so init second entry's tag
    to_cp->tag_at_put(to_i + 1, JVM_CONSTANT_Invalid);
  } break;

  case JVM_CONSTANT_Fieldref:
  {
    int class_index = from_cp->uncached_klass_ref_index_at(from_i);
    int name_and_type_index = from_cp->uncached_name_and_type_ref_index_at(from_i);
    to_cp->field_at_put(to_i, class_index, name_and_type_index);
  } break;

  case JVM_CONSTANT_Float:
  {
    jfloat f = from_cp->float_at(from_i);
    to_cp->float_at_put(to_i, f);
  } break;

  case JVM_CONSTANT_Integer:
  {
    jint i = from_cp->int_at(from_i);
    to_cp->int_at_put(to_i, i);
  } break;

  case JVM_CONSTANT_InterfaceMethodref:
  {
    int class_index = from_cp->uncached_klass_ref_index_at(from_i);
    int name_and_type_index = from_cp->uncached_name_and_type_ref_index_at(from_i);
    to_cp->interface_method_at_put(to_i, class_index, name_and_type_index);
  } break;

  case JVM_CONSTANT_Long:
  {
    jlong l = from_cp->long_at(from_i);
    to_cp->long_at_put(to_i, l);
    // long takes two constant pool entries so init second entry's tag
    to_cp->tag_at_put(to_i + 1, JVM_CONSTANT_Invalid);
  } break;

  case JVM_CONSTANT_Methodref:
  {
    int class_index = from_cp->uncached_klass_ref_index_at(from_i);
    int name_and_type_index = from_cp->uncached_name_and_type_ref_index_at(from_i);
    to_cp->method_at_put(to_i, class_index, name_and_type_index);
  } break;

  case JVM_CONSTANT_NameAndType:
  {
    int name_ref_index = from_cp->name_ref_index_at(from_i);
    int signature_ref_index = from_cp->signature_ref_index_at(from_i);
    to_cp->name_and_type_at_put(to_i, name_ref_index, signature_ref_index);
  } break;

  case JVM_CONSTANT_StringIndex:
  {
    jint si = from_cp->string_index_at(from_i);
    to_cp->string_index_at_put(to_i, si);
  } break;

  case JVM_CONSTANT_Class:
  case JVM_CONSTANT_UnresolvedClass:
  case JVM_CONSTANT_UnresolvedClassInError:
  {
    // Revert to JVM_CONSTANT_ClassIndex
    int name_index = from_cp->klass_slot_at(from_i).name_index();
    assert(from_cp->tag_at(name_index).is_symbol(), "sanity");
    to_cp->klass_index_at_put(to_i, name_index);
  } break;

  case JVM_CONSTANT_String:
  {
    Symbol* s = from_cp->unresolved_string_at(from_i);
    to_cp->unresolved_string_at_put(to_i, s);
  } break;

  case JVM_CONSTANT_Utf8:
  {
    Symbol* s = from_cp->symbol_at(from_i);
    // Need to increase refcount, the old one will be thrown away and deferenced
    s->increment_refcount();
    to_cp->symbol_at_put(to_i, s);
  } break;

  case JVM_CONSTANT_MethodType:
  case JVM_CONSTANT_MethodTypeInError:
  {
    jint k = from_cp->method_type_index_at(from_i);
    to_cp->method_type_index_at_put(to_i, k);
  } break;

  case JVM_CONSTANT_MethodHandle:
  case JVM_CONSTANT_MethodHandleInError:
  {
    int k1 = from_cp->method_handle_ref_kind_at(from_i);
    int k2 = from_cp->method_handle_index_at(from_i);
    to_cp->method_handle_index_at_put(to_i, k1, k2);
  } break;

  case JVM_CONSTANT_Dynamic:
  case JVM_CONSTANT_DynamicInError:
  {
    int k1 = from_cp->bootstrap_methods_attribute_index(from_i);
    int k2 = from_cp->bootstrap_name_and_type_ref_index_at(from_i);
    k1 += operand_array_length(to_cp->operands());  // to_cp might already have operands
    to_cp->dynamic_constant_at_put(to_i, k1, k2);
  } break;

  case JVM_CONSTANT_InvokeDynamic:
  {
    int k1 = from_cp->bootstrap_methods_attribute_index(from_i);
    int k2 = from_cp->bootstrap_name_and_type_ref_index_at(from_i);
    k1 += operand_array_length(to_cp->operands());  // to_cp might already have operands
    to_cp->invoke_dynamic_at_put(to_i, k1, k2);
  } break;

  // Invalid is used as the tag for the second constant pool entry
  // occupied by JVM_CONSTANT_Double or JVM_CONSTANT_Long. It should
  // not be seen by itself.
  case JVM_CONSTANT_Invalid: // fall through

  default:
  {
    ShouldNotReachHere();
  } break;
  }
} // end copy_entry_to()

// Search constant pool search_cp for an entry that matches this
// constant pool's entry at pattern_i. Returns the index of a
// matching entry or zero (0) if there is no matching entry.
int ConstantPool::find_matching_entry(int pattern_i,
      const constantPoolHandle& search_cp) {

  // index zero (0) is not used
  for (int i = 1; i < search_cp->length(); i++) {
    bool found = compare_entry_to(pattern_i, search_cp, i);
    if (found) {
      return i;
    }
  }

  return 0;  // entry not found; return unused index zero (0)
} // end find_matching_entry()


// Compare this constant pool's bootstrap specifier at idx1 to the constant pool
// cp2's bootstrap specifier at idx2.
bool ConstantPool::compare_operand_to(int idx1, const constantPoolHandle& cp2, int idx2) {
  BSMAttributeEntry* e1 = bsm_attribute_entry(idx1);
  BSMAttributeEntry* e2 = cp2->bsm_attribute_entry(idx2);
  int k1 = e1->bootstrap_method_index();
  int k2 = e2->bootstrap_method_index();
  bool match = compare_entry_to(k1, cp2, k2);

  if (!match) {
    return false;
  }
  int argc = e1->argument_count();
  if (argc == e2->argument_count()) {
    for (int j = 0; j < argc; j++) {
      k1 = e1->argument_index(j);
      k2 = e2->argument_index(j);
      match = compare_entry_to(k1, cp2, k2);
      if (!match) {
        return false;
      }
    }
    return true;           // got through loop; all elements equal
  }
  return false;
} // end compare_operand_to()

// Search constant pool search_cp for a bootstrap specifier that matches
// this constant pool's bootstrap specifier data at pattern_i index.
// Return the index of a matching bootstrap attribute record or (-1) if there is no match.
int ConstantPool::find_matching_operand(int pattern_i,
                    const constantPoolHandle& search_cp, int search_len) {
  for (int i = 0; i < search_len; i++) {
    bool found = compare_operand_to(pattern_i, search_cp, i);
    if (found) {
      return i;
    }
  }
  return -1;  // bootstrap specifier data not found; return unused index (-1)
} // end find_matching_operand()


#ifndef PRODUCT

const char* ConstantPool::printable_name_at(int cp_index) {

  constantTag tag = tag_at(cp_index);

  if (tag.is_string()) {
    return string_at_noresolve(cp_index);
  } else if (tag.is_klass() || tag.is_unresolved_klass()) {
    return klass_name_at(cp_index)->as_C_string();
  } else if (tag.is_symbol()) {
    return symbol_at(cp_index)->as_C_string();
  }
  return "";
}

#endif // PRODUCT


// Returns size of constant pool entry.
jint ConstantPool::cpool_entry_size(jint idx) {
  switch(tag_at(idx).value()) {
    case JVM_CONSTANT_Invalid:
    case JVM_CONSTANT_Unicode:
      return 1;

    case JVM_CONSTANT_Utf8:
      return 3 + symbol_at(idx)->utf8_length();

    case JVM_CONSTANT_Class:
    case JVM_CONSTANT_String:
    case JVM_CONSTANT_ClassIndex:
    case JVM_CONSTANT_UnresolvedClass:
    case JVM_CONSTANT_UnresolvedClassInError:
    case JVM_CONSTANT_StringIndex:
    case JVM_CONSTANT_MethodType:
    case JVM_CONSTANT_MethodTypeInError:
      return 3;

    case JVM_CONSTANT_MethodHandle:
    case JVM_CONSTANT_MethodHandleInError:
      return 4; //tag, ref_kind, ref_index

    case JVM_CONSTANT_Integer:
    case JVM_CONSTANT_Float:
    case JVM_CONSTANT_Fieldref:
    case JVM_CONSTANT_Methodref:
    case JVM_CONSTANT_InterfaceMethodref:
    case JVM_CONSTANT_NameAndType:
      return 5;

    case JVM_CONSTANT_Dynamic:
    case JVM_CONSTANT_DynamicInError:
    case JVM_CONSTANT_InvokeDynamic:
      // u1 tag, u2 bsm, u2 nt
      return 5;

    case JVM_CONSTANT_Long:
    case JVM_CONSTANT_Double:
      return 9;
  }
  assert(false, "cpool_entry_size: Invalid constant pool entry tag");
  return 1;
} /* end cpool_entry_size */


// SymbolHash is used to find a constant pool index from a string.
// This function fills in SymbolHashs, one for utf8s and one for
// class names, returns size of the cpool raw bytes.
jint ConstantPool::hash_entries_to(SymbolHash *symmap,
                                   SymbolHash *classmap) {
  jint size = 0;

  for (u2 idx = 1; idx < length(); idx++) {
    u2 tag = tag_at(idx).value();
    size += cpool_entry_size(idx);

    switch(tag) {
      case JVM_CONSTANT_Utf8: {
        Symbol* sym = symbol_at(idx);
        symmap->add_if_absent(sym, idx);
        break;
      }
      case JVM_CONSTANT_Class:
      case JVM_CONSTANT_UnresolvedClass:
      case JVM_CONSTANT_UnresolvedClassInError: {
        Symbol* sym = klass_name_at(idx);
        classmap->add_if_absent(sym, idx);
        break;
      }
      case JVM_CONSTANT_Long:
      case JVM_CONSTANT_Double: {
        idx++; // Both Long and Double take two cpool slots
        break;
      }
    }
  }
  return size;
} /* end hash_utf8_entries_to */


// Copy cpool bytes.
// Returns:
//    0, in case of OutOfMemoryError
//   -1, in case of internal error
//  > 0, count of the raw cpool bytes that have been copied
int ConstantPool::copy_cpool_bytes(int cpool_size,
                                   SymbolHash* tbl,
                                   unsigned char *bytes) {
  u2   idx1, idx2;
  jint size  = 0;
  jint cnt   = length();
  unsigned char *start_bytes = bytes;

  for (jint idx = 1; idx < cnt; idx++) {
    u1   tag      = tag_at(idx).value();
    jint ent_size = cpool_entry_size(idx);

    assert(size + ent_size <= cpool_size, "Size mismatch");

    *bytes = tag;
    switch(tag) {
      case JVM_CONSTANT_Invalid: {
        break;
      }
      case JVM_CONSTANT_Unicode: {
        assert(false, "Wrong constant pool tag: JVM_CONSTANT_Unicode");
        break;
      }
      case JVM_CONSTANT_Utf8: {
        Symbol* sym = symbol_at(idx);
        char*     str = sym->as_utf8();
        // Warning! It's crashing on x86 with len = sym->utf8_length()
        int       len = (int) strlen(str);
        Bytes::put_Java_u2((address) (bytes+1), (u2) len);
        for (int i = 0; i < len; i++) {
            bytes[3+i] = (u1) str[i];
        }
        break;
      }
      case JVM_CONSTANT_Integer: {
        jint val = int_at(idx);
        Bytes::put_Java_u4((address) (bytes+1), *(u4*)&val);
        break;
      }
      case JVM_CONSTANT_Float: {
        jfloat val = float_at(idx);
        Bytes::put_Java_u4((address) (bytes+1), *(u4*)&val);
        break;
      }
      case JVM_CONSTANT_Long: {
        jlong val = long_at(idx);
        Bytes::put_Java_u8((address) (bytes+1), *(u8*)&val);
        idx++;             // Long takes two cpool slots
        break;
      }
      case JVM_CONSTANT_Double: {
        jdouble val = double_at(idx);
        Bytes::put_Java_u8((address) (bytes+1), *(u8*)&val);
        idx++;             // Double takes two cpool slots
        break;
      }
      case JVM_CONSTANT_Class:
      case JVM_CONSTANT_UnresolvedClass:
      case JVM_CONSTANT_UnresolvedClassInError: {
        *bytes = JVM_CONSTANT_Class;
        Symbol* sym = klass_name_at(idx);
        idx1 = tbl->symbol_to_value(sym);
        assert(idx1 != 0, "Have not found a hashtable entry");
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        break;
      }
      case JVM_CONSTANT_String: {
        *bytes = JVM_CONSTANT_String;
        Symbol* sym = unresolved_string_at(idx);
        idx1 = tbl->symbol_to_value(sym);
        assert(idx1 != 0, "Have not found a hashtable entry");
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        break;
      }
      case JVM_CONSTANT_Fieldref:
      case JVM_CONSTANT_Methodref:
      case JVM_CONSTANT_InterfaceMethodref: {
        idx1 = uncached_klass_ref_index_at(idx);
        idx2 = uncached_name_and_type_ref_index_at(idx);
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        Bytes::put_Java_u2((address) (bytes+3), idx2);
        break;
      }
      case JVM_CONSTANT_NameAndType: {
        idx1 = name_ref_index_at(idx);
        idx2 = signature_ref_index_at(idx);
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        Bytes::put_Java_u2((address) (bytes+3), idx2);
        break;
      }
      case JVM_CONSTANT_ClassIndex: {
        *bytes = JVM_CONSTANT_Class;
        idx1 = checked_cast<u2>(klass_index_at(idx));
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        break;
      }
      case JVM_CONSTANT_StringIndex: {
        *bytes = JVM_CONSTANT_String;
        idx1 = checked_cast<u2>(string_index_at(idx));
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        break;
      }
      case JVM_CONSTANT_MethodHandle:
      case JVM_CONSTANT_MethodHandleInError: {
        *bytes = JVM_CONSTANT_MethodHandle;
        int kind = method_handle_ref_kind_at(idx);
        idx1 = checked_cast<u2>(method_handle_index_at(idx));
        *(bytes+1) = (unsigned char) kind;
        Bytes::put_Java_u2((address) (bytes+2), idx1);
        break;
      }
      case JVM_CONSTANT_MethodType:
      case JVM_CONSTANT_MethodTypeInError: {
        *bytes = JVM_CONSTANT_MethodType;
        idx1 = checked_cast<u2>(method_type_index_at(idx));
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        break;
      }
      case JVM_CONSTANT_Dynamic:
      case JVM_CONSTANT_DynamicInError: {
        *bytes = tag;
        idx1 = extract_low_short_from_int(*int_at_addr(idx));
        idx2 = extract_high_short_from_int(*int_at_addr(idx));
        assert(idx2 == bootstrap_name_and_type_ref_index_at(idx), "correct half of u4");
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        Bytes::put_Java_u2((address) (bytes+3), idx2);
        break;
      }
      case JVM_CONSTANT_InvokeDynamic: {
        *bytes = tag;
        idx1 = extract_low_short_from_int(*int_at_addr(idx));
        idx2 = extract_high_short_from_int(*int_at_addr(idx));
        assert(idx2 == bootstrap_name_and_type_ref_index_at(idx), "correct half of u4");
        Bytes::put_Java_u2((address) (bytes+1), idx1);
        Bytes::put_Java_u2((address) (bytes+3), idx2);
        break;
      }
    }
    bytes += ent_size;
    size  += ent_size;
  }
  assert(size == cpool_size, "Size mismatch");

  return (int)(bytes - start_bytes);
} /* end copy_cpool_bytes */

bool ConstantPool::is_maybe_on_stack() const {
  // This method uses the similar logic as nmethod::is_maybe_on_stack()
  if (!Continuations::enabled()) {
    return false;
  }

  // If the condition below is true, it means that the nmethod was found to
  // be alive the previous completed marking cycle.
  return cache()->gc_epoch() >= CodeCache::previous_completed_gc_marking_cycle();
}

// For redefinition, if any methods found in loom stack chunks, the gc_epoch is
// recorded in their constant pool cache. The on_stack-ness of the constant pool controls whether
// memory for the method is reclaimed.
bool ConstantPool::on_stack() const {
  if ((_flags &_on_stack) != 0) {
    return true;
  }

  if (_cache == nullptr) {
    return false;
  }

  return is_maybe_on_stack();
}

void ConstantPool::set_on_stack(const bool value) {
  if (value) {
    // Only record if it's not already set.
    if (!on_stack()) {
      assert(!is_shared(), "should always be set for shared constant pools");
      _flags |= _on_stack;
      MetadataOnStackMark::record(this);
    }
  } else {
    // Clearing is done single-threadedly.
    if (!is_shared()) {
      _flags &= (u2)(~_on_stack);
    }
  }
}

// Printing

void ConstantPool::print_on(outputStream* st) const {
  assert(is_constantPool(), "must be constantPool");
  st->print_cr("%s", internal_name());
  if (flags() != 0) {
    st->print(" - flags: 0x%x", flags());
    if (has_preresolution()) st->print(" has_preresolution");
    if (on_stack()) st->print(" on_stack");
    st->cr();
  }
  if (pool_holder() != nullptr) {
    st->print_cr(" - holder: " PTR_FORMAT, p2i(pool_holder()));
  }
  st->print_cr(" - cache: " PTR_FORMAT, p2i(cache()));
  st->print_cr(" - resolved_references: " PTR_FORMAT, p2i(resolved_references_or_null()));
  st->print_cr(" - reference_map: " PTR_FORMAT, p2i(reference_map()));
  st->print_cr(" - resolved_klasses: " PTR_FORMAT, p2i(resolved_klasses()));
  st->print_cr(" - cp length: %d", length());

  for (int index = 1; index < length(); index++) {      // Index 0 is unused
    ((ConstantPool*)this)->print_entry_on(index, st);
    switch (tag_at(index).value()) {
      case JVM_CONSTANT_Long :
      case JVM_CONSTANT_Double :
        index++;   // Skip entry following eigth-byte constant
    }

  }
  st->cr();
}

// Print one constant pool entry
void ConstantPool::print_entry_on(const int cp_index, outputStream* st) {
  EXCEPTION_MARK;
  st->print(" - %3d : ", cp_index);
  tag_at(cp_index).print_on(st);
  st->print(" : ");
  switch (tag_at(cp_index).value()) {
    case JVM_CONSTANT_Class :
      { Klass* k = klass_at(cp_index, CATCH);
        guarantee(k != nullptr, "need klass");
        k->print_value_on(st);
        st->print(" {" PTR_FORMAT "}", p2i(k));
      }
      break;
    case JVM_CONSTANT_Fieldref :
    case JVM_CONSTANT_Methodref :
    case JVM_CONSTANT_InterfaceMethodref :
      st->print("klass_index=%d", uncached_klass_ref_index_at(cp_index));
      st->print(" name_and_type_index=%d", uncached_name_and_type_ref_index_at(cp_index));
      break;
    case JVM_CONSTANT_String :
      unresolved_string_at(cp_index)->print_value_on(st);
      break;
    case JVM_CONSTANT_Integer :
      st->print("%d", int_at(cp_index));
      break;
    case JVM_CONSTANT_Float :
      st->print("%f", float_at(cp_index));
      break;
    case JVM_CONSTANT_Long :
      st->print_jlong(long_at(cp_index));
      break;
    case JVM_CONSTANT_Double :
      st->print("%lf", double_at(cp_index));
      break;
    case JVM_CONSTANT_NameAndType :
      st->print("name_index=%d", name_ref_index_at(cp_index));
      st->print(" signature_index=%d", signature_ref_index_at(cp_index));
      break;
    case JVM_CONSTANT_Utf8 :
      symbol_at(cp_index)->print_value_on(st);
      break;
    case JVM_CONSTANT_ClassIndex: {
        int name_index = *int_at_addr(cp_index);
        st->print("klass_index=%d ", name_index);
        symbol_at(name_index)->print_value_on(st);
      }
      break;
    case JVM_CONSTANT_UnresolvedClass :               // fall-through
    case JVM_CONSTANT_UnresolvedClassInError: {
        CPKlassSlot kslot = klass_slot_at(cp_index);
        int resolved_klass_index = kslot.resolved_klass_index();
        int name_index = kslot.name_index();
        assert(tag_at(name_index).is_symbol(), "sanity");
        symbol_at(name_index)->print_value_on(st);
      }
      break;
    case JVM_CONSTANT_MethodHandle :
    case JVM_CONSTANT_MethodHandleInError :
      st->print("ref_kind=%d", method_handle_ref_kind_at(cp_index));
      st->print(" ref_index=%d", method_handle_index_at(cp_index));
      break;
    case JVM_CONSTANT_MethodType :
    case JVM_CONSTANT_MethodTypeInError :
      st->print("signature_index=%d", method_type_index_at(cp_index));
      break;
    case JVM_CONSTANT_Dynamic :
    case JVM_CONSTANT_DynamicInError :
      {
        st->print("bootstrap_method_index=%d", bootstrap_method_ref_index_at(cp_index));
        st->print(" type_index=%d", bootstrap_name_and_type_ref_index_at(cp_index));
        int argc = bootstrap_argument_count_at(cp_index);
        if (argc > 0) {
          for (int arg_i = 0; arg_i < argc; arg_i++) {
            int arg = bootstrap_argument_index_at(cp_index, arg_i);
            st->print((arg_i == 0 ? " arguments={%d" : ", %d"), arg);
          }
          st->print("}");
        }
      }
      break;
    case JVM_CONSTANT_InvokeDynamic :
      {
        st->print("bootstrap_method_index=%d", bootstrap_method_ref_index_at(cp_index));
        st->print(" name_and_type_index=%d", bootstrap_name_and_type_ref_index_at(cp_index));
        int argc = bootstrap_argument_count_at(cp_index);
        if (argc > 0) {
          for (int arg_i = 0; arg_i < argc; arg_i++) {
            int arg = bootstrap_argument_index_at(cp_index, arg_i);
            st->print((arg_i == 0 ? " arguments={%d" : ", %d"), arg);
          }
          st->print("}");
        }
      }
      break;
    default:
      ShouldNotReachHere();
      break;
  }
  st->cr();
}

void ConstantPool::print_value_on(outputStream* st) const {
  assert(is_constantPool(), "must be constantPool");
  st->print("constant pool [%d]", length());
  if (has_preresolution()) st->print("/preresolution");
  if (operands() != nullptr)  st->print("/operands[%d]", operands()->length());
  print_address_on(st);
  if (pool_holder() != nullptr) {
    st->print(" for ");
    pool_holder()->print_value_on(st);
    bool extra = (pool_holder()->constants() != this);
    if (extra)  st->print(" (extra)");
  }
  if (cache() != nullptr) {
    st->print(" cache=" PTR_FORMAT, p2i(cache()));
  }
}

// Verification

void ConstantPool::verify_on(outputStream* st) {
  guarantee(is_constantPool(), "object must be constant pool");
  for (int i = 0; i< length();  i++) {
    constantTag tag = tag_at(i);
    if (tag.is_klass() || tag.is_unresolved_klass()) {
      guarantee(klass_name_at(i)->refcount() != 0, "should have nonzero reference count");
    } else if (tag.is_symbol()) {
      Symbol* entry = symbol_at(i);
      guarantee(entry->refcount() != 0, "should have nonzero reference count");
    } else if (tag.is_string()) {
      Symbol* entry = unresolved_string_at(i);
      guarantee(entry->refcount() != 0, "should have nonzero reference count");
    }
  }
  if (pool_holder() != nullptr) {
    // Note: pool_holder() can be null in temporary constant pools
    // used during constant pool merging
    guarantee(pool_holder()->is_klass(),    "should be klass");
  }
}
