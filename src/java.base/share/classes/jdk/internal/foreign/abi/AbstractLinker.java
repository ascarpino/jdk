/*
 * Copyright (c) 2022, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 */
package jdk.internal.foreign.abi;

import jdk.internal.foreign.SystemLookup;
import jdk.internal.foreign.Utils;
import jdk.internal.foreign.abi.aarch64.linux.LinuxAArch64Linker;
import jdk.internal.foreign.abi.aarch64.macos.MacOsAArch64Linker;
import jdk.internal.foreign.abi.aarch64.windows.WindowsAArch64Linker;
import jdk.internal.foreign.abi.fallback.FallbackLinker;
import jdk.internal.foreign.abi.ppc64.aix.AixPPC64Linker;
import jdk.internal.foreign.abi.ppc64.linux.LinuxPPC64Linker;
import jdk.internal.foreign.abi.ppc64.linux.LinuxPPC64leLinker;
import jdk.internal.foreign.abi.riscv64.linux.LinuxRISCV64Linker;
import jdk.internal.foreign.abi.s390.linux.LinuxS390Linker;
import jdk.internal.foreign.abi.x64.sysv.SysVx64Linker;
import jdk.internal.foreign.abi.x64.windows.Windowsx64Linker;
import jdk.internal.foreign.layout.AbstractLayout;
import jdk.internal.reflect.CallerSensitive;
import jdk.internal.reflect.Reflection;

import java.lang.foreign.AddressLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.GroupLayout;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.PaddingLayout;
import java.lang.foreign.SequenceLayout;
import java.lang.foreign.StructLayout;
import java.lang.foreign.UnionLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public abstract sealed class AbstractLinker implements Linker permits LinuxAArch64Linker, MacOsAArch64Linker,
                                                                      SysVx64Linker, WindowsAArch64Linker,
                                                                      Windowsx64Linker, AixPPC64Linker,
                                                                      LinuxPPC64Linker, LinuxPPC64leLinker,
                                                                      LinuxRISCV64Linker, LinuxS390Linker,
                                                                      FallbackLinker {

    public interface UpcallStubFactory {
        MemorySegment makeStub(MethodHandle target, Arena arena);
    }

    private record LinkRequest(FunctionDescriptor descriptor, LinkerOptions options) {
        // Overrides for boot performance
        @Override
        public boolean equals(Object obj) {
            return obj instanceof LinkRequest other &&
                    other.descriptor.equals(descriptor) &&
                    other.options.equals(options);
        }

        @Override
        public int hashCode() {
            return descriptor.hashCode() * 1237 + options.hashCode();
        }
    }
    private final SoftReferenceCache<LinkRequest, MethodHandle> DOWNCALL_CACHE = new SoftReferenceCache<>();
    private final SoftReferenceCache<LinkRequest, UpcallStubFactory> UPCALL_CACHE = new SoftReferenceCache<>();
    private final Set<MemoryLayout> CANONICAL_LAYOUTS_CACHE = new HashSet<>(canonicalLayouts().values());

    @Override
    @CallerSensitive
    public final MethodHandle downcallHandle(MemorySegment symbol, FunctionDescriptor function, Option... options) {
        Reflection.ensureNativeAccess(Reflection.getCallerClass(), Linker.class, "downcallHandle", false);
        SharedUtils.checkSymbol(symbol);
        return downcallHandle0(function, options).bindTo(symbol);
    }

    @Override
    @CallerSensitive
    public final MethodHandle downcallHandle(FunctionDescriptor function, Option... options) {
        Reflection.ensureNativeAccess(Reflection.getCallerClass(), Linker.class, "downcallHandle", false);
        return downcallHandle0(function, options);
    }

    private MethodHandle downcallHandle0(FunctionDescriptor function, Option... options) {
        Objects.requireNonNull(function);
        Objects.requireNonNull(options);
        checkLayouts(function);
        function = stripNames(function);
        LinkerOptions optionSet = LinkerOptions.forDowncall(function, options);
        validateVariadicLayouts(function, optionSet);

        return DOWNCALL_CACHE.get(new LinkRequest(function, optionSet), linkRequest ->  {
            FunctionDescriptor fd = linkRequest.descriptor();
            MethodType type = fd.toMethodType();
            MethodHandle handle = arrangeDowncall(type, fd, linkRequest.options());
            handle = SharedUtils.maybeCheckCaptureSegment(handle, linkRequest.options());
            handle = SharedUtils.maybeInsertAllocator(fd, handle);
            return handle;
        });
    }

    protected abstract MethodHandle arrangeDowncall(MethodType inferredMethodType, FunctionDescriptor function, LinkerOptions options);

    @Override
    @CallerSensitive
    public final MemorySegment upcallStub(MethodHandle target, FunctionDescriptor function, Arena arena, Linker.Option... options) {
        Reflection.ensureNativeAccess(Reflection.getCallerClass(), Linker.class, "upcallStub", false);
        Objects.requireNonNull(arena);
        Objects.requireNonNull(target);
        Objects.requireNonNull(function);
        checkLayouts(function);
        SharedUtils.checkExceptions(target);
        function = stripNames(function);
        LinkerOptions optionSet = LinkerOptions.forUpcall(function, options);

        MethodType type = function.toMethodType();
        if (!type.equals(target.type())) {
            throw new IllegalArgumentException("Wrong method handle type: " + target.type());
        }

        UpcallStubFactory factory = UPCALL_CACHE.get(new LinkRequest(function, optionSet), linkRequest ->
            arrangeUpcall(type, linkRequest.descriptor(), linkRequest.options()));
        return factory.makeStub(target, arena);
    }

    protected abstract UpcallStubFactory arrangeUpcall(MethodType targetType, FunctionDescriptor function, LinkerOptions options);

    @Override
    public SystemLookup defaultLookup() {
        return SystemLookup.getInstance();
    }

    // C spec mandates that variadic arguments smaller than int are promoted to int,
    // and float is promoted to double
    // See: https://en.cppreference.com/w/c/language/conversion#Default_argument_promotions
    // We reject the corresponding layouts here, to avoid issues where unsigned values
    // are sign extended when promoted. (as we don't have a way to unambiguously represent signed-ness atm).
    private void validateVariadicLayouts(FunctionDescriptor function, LinkerOptions optionSet) {
        if (optionSet.isVariadicFunction()) {
            List<MemoryLayout> argumentLayouts = function.argumentLayouts();
            List<MemoryLayout> variadicLayouts = argumentLayouts.subList(optionSet.firstVariadicArgIndex(), argumentLayouts.size());

            for (MemoryLayout variadicLayout : variadicLayouts) {
                if (variadicLayout.equals(ValueLayout.JAVA_BOOLEAN)
                    || variadicLayout.equals(ValueLayout.JAVA_BYTE)
                    || variadicLayout.equals(ValueLayout.JAVA_CHAR)
                    || variadicLayout.equals(ValueLayout.JAVA_SHORT)
                    || variadicLayout.equals(ValueLayout.JAVA_FLOAT)) {
                    throw new IllegalArgumentException("Invalid variadic argument layout: " + variadicLayout);
                }
            }
        }
    }

    private void checkLayouts(FunctionDescriptor descriptor) {
        descriptor.returnLayout().ifPresent(this::checkLayout);
        descriptor.argumentLayouts().forEach(this::checkLayout);
    }

    private void checkLayout(MemoryLayout layout) {
        // Note: we should not worry about padding layouts, as they cannot be present in a function descriptor
        if (layout instanceof SequenceLayout) {
            throw new IllegalArgumentException("Unsupported layout: " + layout);
        } else {
            checkLayoutRecursive(layout);
        }
    }

    // some ABIs have special handling for struct members
    protected void checkStructMember(MemoryLayout member, long offset) {
        checkLayoutRecursive(member);
    }

    private void checkLayoutRecursive(MemoryLayout layout) {
        if (layout instanceof ValueLayout vl) {
            checkSupported(vl);
        } else if (layout instanceof StructLayout sl) {
            checkHasNaturalAlignment(layout);
            long offset = 0;
            long lastUnpaddedOffset = 0;
            PaddingLayout preceedingPadding = null;
            for (MemoryLayout member : sl.memberLayouts()) {
                // check element offset before recursing so that an error points at the
                // outermost layout first
                checkMemberOffset(sl, member, lastUnpaddedOffset, offset);
                checkStructMember(member, offset);

                offset += member.byteSize();
                if (!(member instanceof PaddingLayout pl)) {
                    lastUnpaddedOffset = offset;
                    if (preceedingPadding != null) {
                        preceedingPadding = null;
                    }
                } else {
                    if (preceedingPadding != null) {
                        throw new IllegalArgumentException("The padding layout " + pl +
                                " was preceded by another padding layout " + preceedingPadding +
                                inMessage(sl));
                    }
                    preceedingPadding = pl;
                }
            }
            checkNotAllPadding(sl);
            checkGroup(sl, lastUnpaddedOffset);
        } else if (layout instanceof UnionLayout ul) {
            checkHasNaturalAlignment(layout);
            // We need to know this up front
            long maxUnpaddedLayout = ul.memberLayouts().stream()
                    .filter(l -> !(l instanceof PaddingLayout))
                    .mapToLong(MemoryLayout::byteSize)
                    .max()
                    .orElse(0);

            boolean hasPadding = false;

            for (MemoryLayout member : ul.memberLayouts()) {
                checkLayoutRecursive(member);
                if (member instanceof PaddingLayout pl) {
                    if (hasPadding) {
                        throw new IllegalArgumentException("More than one padding" + inMessage(ul));
                    }
                    hasPadding = true;
                    if (pl.byteSize() <= maxUnpaddedLayout) {
                        throw new IllegalArgumentException("Superfluous padding " + pl + inMessage(ul));
                    }
                }
            }
            checkGroup(ul, maxUnpaddedLayout);
        } else if (layout instanceof SequenceLayout sl) {
            checkHasNaturalAlignment(layout);
            if (sl.elementLayout() instanceof PaddingLayout pl) {
                throw memberException(sl, pl,
                        "not supported because a sequence of a padding layout is not allowed");
            }
            checkLayoutRecursive(sl.elementLayout());
        }
    }

    // check elements are not all padding layouts
    private static void checkNotAllPadding(StructLayout sl) {
        if (!sl.memberLayouts().isEmpty() && sl.memberLayouts().stream().allMatch(e -> e instanceof PaddingLayout)) {
            throw new IllegalArgumentException("Layout '" + sl + "' is non-empty and only has padding layouts");
        }
    }

    // check trailing padding
    private static void checkGroup(GroupLayout gl, long maxUnpaddedOffset) {
        long expectedSize = Utils.alignUp(maxUnpaddedOffset, gl.byteAlignment());
        if (gl.byteSize() != expectedSize) {
            throw new IllegalArgumentException("Layout '" + gl + "' has unexpected size: "
                    + gl.byteSize() + " != " + expectedSize);
        }
    }

    private static String inMessage(GroupLayout gl) {
        return " in " + gl;
    }

    // checks both that there is no excess padding between 'memberLayout' and
    // the previous layout
    private static void checkMemberOffset(StructLayout parent, MemoryLayout memberLayout,
                                          long lastUnpaddedOffset, long offset) {
        long expectedOffset = Utils.alignUp(lastUnpaddedOffset, memberLayout.byteAlignment());
        if (expectedOffset != offset) {
            throw memberException(parent, memberLayout,
                    "found at unexpected offset: " + offset + " != " + expectedOffset);
        }
    }

    private static IllegalArgumentException memberException(MemoryLayout parent,
                                                            MemoryLayout member,
                                                            String info) {
        return new IllegalArgumentException(
                "Member layout '" + member + "', of '" + parent + "' " + info);
    }

    private void checkSupported(ValueLayout valueLayout) {
        valueLayout = valueLayout.withoutName();
        if (valueLayout instanceof AddressLayout addressLayout) {
            valueLayout = addressLayout.withoutTargetLayout();
        }
        if (!CANONICAL_LAYOUTS_CACHE.contains(valueLayout.withoutName())) {
            throw new IllegalArgumentException("Unsupported layout: " + valueLayout);
        }
    }

    private void checkHasNaturalAlignment(MemoryLayout layout) {
        if (!((AbstractLayout<?>) layout).hasNaturalAlignment()) {
            throw new IllegalArgumentException("Layout alignment must be natural alignment: " + layout);
        }
    }

    @SuppressWarnings("restricted")
    private static MemoryLayout stripNames(MemoryLayout ml) {
        // we don't care about transferring alignment and byte order here
        // since the linker already restricts those such that they will always be the same
        return switch (ml) {
            case StructLayout sl -> MemoryLayout.structLayout(stripNames(sl.memberLayouts()));
            case UnionLayout ul -> MemoryLayout.unionLayout(stripNames(ul.memberLayouts()));
            case SequenceLayout sl -> MemoryLayout.sequenceLayout(sl.elementCount(), stripNames(sl.elementLayout()));
            case AddressLayout al -> {
                var stripped = al.withoutName();
                var target = al.targetLayout();
                if (target.isPresent())
                    stripped = stripped.withTargetLayout(stripNames(target.get()));
                yield stripped;
            }
            default -> ml.withoutName(); // ValueLayout and PaddingLayout
        };
    }

    private static MemoryLayout[] stripNames(List<MemoryLayout> layouts) {
        var ret = new MemoryLayout[layouts.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = stripNames(layouts.get(i));
        }
        return ret;
    }

    private static FunctionDescriptor stripNames(FunctionDescriptor function) {
        var retLayout = function.returnLayout();
        if (retLayout.isEmpty()) {
            return FunctionDescriptor.ofVoid(stripNames(function.argumentLayouts()));
        }
        return FunctionDescriptor.of(stripNames(retLayout.get()), stripNames(function.argumentLayouts()));
    }
}
