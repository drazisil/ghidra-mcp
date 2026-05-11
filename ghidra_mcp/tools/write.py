"""
Write tools: rename functions, set signatures, apply struct members.
Each tool opens and commits its own transaction.
"""
from __future__ import annotations


def register(mcp, get_program, get_project):
    """Register all write tools onto the FastMCP instance."""

    @mcp.tool()
    def rename_function(address: str, new_name: str) -> str:
        """
        Rename the function at the given hex address.
        Example: rename_function('0055e190', 'GameSetup_Init')
        """
        from ghidra.program.model.symbol import SourceType
        from ghidra_mcp.util import resolve_function

        program = get_program()
        project = get_project()
        fn = resolve_function(program, address)
        old_name = fn.getName()

        tx = program.startTransaction(f"rename {old_name} -> {new_name}")
        success = False
        try:
            fn.setName(new_name, SourceType.USER_DEFINED)
            success = True
        finally:
            program.endTransaction(tx, success)

        if success:
            project.save(program)
            return f"Renamed {fn.getEntryPoint()} : {old_name!r} → {new_name!r}"
        return f"[rename failed]"

    @mcp.tool()
    def set_function_comment(name_or_address: str, comment: str) -> str:
        """
        Set the plate (header) comment on a function.
        """
        from ghidra.program.model.listing import CodeUnit
        from ghidra_mcp.util import resolve_function

        program = get_program()
        project = get_project()
        fn = resolve_function(program, name_or_address)
        listing = program.getListing()
        cu = listing.getCodeUnitAt(fn.getEntryPoint())

        tx = program.startTransaction(f"comment {fn.getName()}")
        success = False
        try:
            cu.setComment(CodeUnit.PLATE_COMMENT, comment)
            success = True
        finally:
            program.endTransaction(tx, success)

        if success:
            project.save(program)
            return f"Comment set on {fn.getName()} @ {fn.getEntryPoint()}"
        return "[comment failed]"

    @mcp.tool()
    def apply_struct_member(
        struct_name: str,
        offset: int,
        type_name: str,
        member_name: str,
    ) -> str:
        """
        Place a field into a struct at the given byte offset.
        Clears conflicting undefined bytes first (replaceAtOffset requires undefined1).
        Example: apply_struct_member('cNPS_GameServer', 1760, 'cUserList', 'mUserList_Added')
        """
        from java.util import ArrayList
        from ghidra.program.model.data import StructureDataType, TypedefDataType

        program = get_program()
        project = get_project()
        dtm = program.getDataTypeManager()

        # Resolve struct
        struct_results = ArrayList()
        dtm.findDataTypes(struct_name, struct_results)
        if struct_results.isEmpty():
            return f"[struct not found: {struct_name!r}]"
        struct_dt = struct_results[0]
        while isinstance(struct_dt, TypedefDataType):
            struct_dt = struct_dt.getDataType()
        if not isinstance(struct_dt, StructureDataType):
            return f"[{struct_name!r} is not a struct]"

        # Resolve member type
        type_results = ArrayList()
        dtm.findDataTypes(type_name, type_results)
        if type_results.isEmpty():
            return f"[type not found: {type_name!r}]"
        member_type = type_results[0]

        member_size = member_type.getLength()
        end_offset = offset + member_size - 1

        tx = dtm.startTransaction(f"apply {member_name} @ [{offset}]")
        success = False
        try:
            # Clear the range to undefined1 so replaceAtOffset accepts it
            for i in range(offset, offset + member_size):
                existing = struct_dt.getComponentAt(i)
                if existing is not None:
                    edt = existing.getDataType()
                    if edt.getName() != "undefined1":
                        struct_dt.clearAtOffset(i)

            struct_dt.replaceAtOffset(offset, member_type, member_size, member_name, "")
            success = True
        finally:
            dtm.endTransaction(tx, success)

        if success:
            project.save(program)
            return (
                f"Applied {type_name} {member_name} at [{offset}] in {struct_name} "
                f"(size={member_size})"
            )
        return "[apply_struct_member failed]"

    @mcp.tool()
    def create_struct(name: str, size: int, category: str = "/") -> str:
        """
        Create a new empty struct data type of the given size.
        category: data type manager path, e.g. '/NPS' or '/' for root.
        """
        from ghidra.program.model.data import StructureDataType, CategoryPath

        program = get_program()
        project = get_project()
        dtm = program.getDataTypeManager()

        cat_path = CategoryPath(category)
        new_struct = StructureDataType(cat_path, name, size, dtm)

        tx = dtm.startTransaction(f"create struct {name}")
        success = False
        try:
            dtm.addDataType(new_struct, None)
            success = True
        finally:
            dtm.endTransaction(tx, success)

        if success:
            project.save(program)
            return f"Created struct {name} ({size} bytes) in {category}"
        return "[create_struct failed]"
