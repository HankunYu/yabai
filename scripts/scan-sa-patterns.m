#import <Foundation/Foundation.h>

#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/osax/arm64_payload.m"

struct pattern_spec {
    const char *name;
    uint64_t (*offset)(NSOperatingSystemVersion);
    const char *(*pattern)(NSOperatingSystemVersion);
};

struct byte_pattern {
    uint8_t *bytes;
    bool *wildcards;
    size_t length;
};

struct selector_spec {
    const char *name;
};

static bool find_section(const uint8_t *data, size_t size, const char *section_name, uint64_t *offset, uint64_t *section_size)
{
    if (size < sizeof(struct mach_header_64)) return false;

    const struct mach_header_64 *header = (const struct mach_header_64 *) data;
    const uint8_t *cursor = data + sizeof(*header);
    const uint8_t *end = cursor + header->sizeofcmds;
    if (end > data + size) return false;

    for (uint32_t i = 0; i < header->ncmds; ++i) {
        const struct load_command *command = (const struct load_command *) cursor;
        if (cursor + sizeof(*command) > end || command->cmdsize < sizeof(*command) || cursor + command->cmdsize > end) return false;

        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *) command;
            const struct section_64 *sections = (const struct section_64 *) (segment + 1);
            for (uint32_t section_index = 0; section_index < segment->nsects; ++section_index) {
                if (strcmp(sections[section_index].sectname, section_name) == 0) {
                    *offset = sections[section_index].offset;
                    *section_size = sections[section_index].size;
                    return *offset <= size && *section_size <= size - *offset;
                }
            }
        }

        cursor += command->cmdsize;
    }

    return false;
}

static bool file_offset_to_vm_address(const uint8_t *data, size_t size, uint64_t file_offset, uint64_t *vm_address)
{
    if (size < sizeof(struct mach_header_64)) return false;

    const struct mach_header_64 *header = (const struct mach_header_64 *) data;
    const uint8_t *cursor = data + sizeof(*header);
    const uint8_t *end = cursor + header->sizeofcmds;
    if (end > data + size) return false;

    for (uint32_t i = 0; i < header->ncmds; ++i) {
        const struct load_command *command = (const struct load_command *) cursor;
        if (cursor + sizeof(*command) > end || command->cmdsize < sizeof(*command) || cursor + command->cmdsize > end) return false;

        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *) command;
            if (file_offset >= segment->fileoff && file_offset < segment->fileoff + segment->filesize) {
                *vm_address = segment->vmaddr + file_offset - segment->fileoff;
                return true;
            }
        }

        cursor += command->cmdsize;
    }

    return false;
}

static bool find_c_string_vm_address(const uint8_t *data, size_t size, const char *text, uint64_t *vm_address)
{
    size_t length = strlen(text) + 1;
    for (uint64_t cursor = 0; cursor + length <= size; ++cursor) {
        if (memcmp(data + cursor, text, length) == 0) {
            return file_offset_to_vm_address(data, size, cursor, vm_address);
        }
    }

    return false;
}

static bool parse_pattern(const char *text, struct byte_pattern *result)
{
    char *copy = strdup(text);
    if (!copy) return false;

    size_t capacity = strlen(text) / 3 + 1;
    result->bytes = calloc(capacity, sizeof(uint8_t));
    result->wildcards = calloc(capacity, sizeof(bool));
    if (!result->bytes || !result->wildcards) {
        free(copy);
        return false;
    }

    char *state = NULL;
    for (char *token = strtok_r(copy, " ", &state); token; token = strtok_r(NULL, " ", &state)) {
        if (token[0] == '?') {
            result->wildcards[result->length] = true;
        } else {
            char *end = NULL;
            unsigned long value = strtoul(token, &end, 16);
            if (!end || *end != '\0' || value > UINT8_MAX) {
                free(copy);
                return false;
            }
            result->bytes[result->length] = (uint8_t) value;
        }
        ++result->length;
    }

    free(copy);
    return result->length != 0;
}

static bool pattern_matches(const uint8_t *data, const struct byte_pattern *pattern)
{
    for (size_t i = 0; i < pattern->length; ++i) {
        if (!pattern->wildcards[i] && data[i] != pattern->bytes[i]) return false;
    }
    return true;
}

static void scan_pattern(const uint8_t *data, size_t size, NSOperatingSystemVersion version, const struct pattern_spec *spec)
{
    uint64_t start = spec->offset(version);
    const char *text = spec->pattern(version);
    struct byte_pattern pattern = {0};

    if (!text) {
        printf("%-18s UNSUPPORTED\n", spec->name);
        return;
    }

    if (!parse_pattern(text, &pattern)) {
        fprintf(stderr, "%s: invalid pattern\n", spec->name);
        return;
    }

    uint64_t scan_size = 0x1286a0;
    uint64_t end = start + scan_size + pattern.length;
    if (start >= size) end = start;
    if (end > size) end = size;

    size_t matches = 0;
    uint64_t first = 0;
    for (uint64_t cursor = start; cursor + pattern.length <= end; ++cursor) {
        if (pattern_matches(data + cursor, &pattern)) {
            if (matches == 0) first = cursor;
            printf("%-18s candidate offset=0x%llx\n", spec->name, cursor);
            ++matches;
        }
    }

    if (matches == 0) {
        printf("%-18s MISSING  scan=[0x%llx,0x%llx) bytes=%zu\n",
               spec->name, start, end, pattern.length);
    } else {
        printf("%-18s MATCH    offset=0x%llx matches=%zu bytes=%zu\n",
               spec->name, first, matches, pattern.length);
    }

    free(pattern.bytes);
    free(pattern.wildcards);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock";
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }

    struct stat stat_buffer;
    if (fstat(fd, &stat_buffer) == -1) {
        fprintf(stderr, "stat %s: %s\n", path, strerror(errno));
        close(fd);
        return EXIT_FAILURE;
    }

    uint8_t *data = mmap(NULL, stat_buffer.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        fprintf(stderr, "mmap %s: %s\n", path, strerror(errno));
        close(fd);
        return EXIT_FAILURE;
    }

    NSOperatingSystemVersion target = { .majorVersion = 27, .minorVersion = 0, .patchVersion = 0 };
    const struct pattern_spec specs[] = {
        { "dock_spaces_5378n", get_dock_spaces_offset, get_dock_spaces_pattern },
        { "dock_spaces_5388g", get_dock_spaces_offset, get_dock_spaces_fallback_pattern },
        { "dppm", get_dppm_offset, get_dppm_pattern },
        { "fix_animation", get_fix_animation_offset, get_fix_animation_pattern },
        { "add_space", get_add_space_offset, get_add_space_pattern },
        { "remove_space", get_remove_space_offset, get_remove_space_pattern },
        { "move_space", get_move_space_offset, get_move_space_pattern },
        { "set_front_window", get_set_front_window_offset, get_set_front_window_pattern },
    };

    printf("Dock: %s\n", path);
    printf("Testing macOS 27 arm64 patterns against %lld bytes\n", stat_buffer.st_size);
    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); ++i) {
        scan_pattern(data, stat_buffer.st_size, target, &specs[i]);
    }

    const struct selector_spec selectors[] = {
        { "_handleEvent:" },
        { "addSpace:forDisplayUUID:" },
        { "doBindingCommand:display:" },
        { "moveSpace:toDisplay:displayUUID:" },
        { "removeSpace:" },
    };

    uint64_t selector_refs_start = 0;
    uint64_t selector_refs_size = 0;
    if (!find_section(data, stat_buffer.st_size, "__objc_selrefs", &selector_refs_start, &selector_refs_size)) {
        fprintf(stderr, "could not locate __objc_selrefs\n");
        munmap(data, stat_buffer.st_size);
        close(fd);
        return EXIT_FAILURE;
    }
    uint64_t selector_refs_end = selector_refs_start + selector_refs_size;

    printf("Objective-C selector references\n");
    for (size_t i = 0; i < sizeof(selectors) / sizeof(selectors[0]); ++i) {
        uint64_t string_address = 0;
        if (!find_c_string_vm_address(data, stat_buffer.st_size, selectors[i].name, &string_address)) {
            printf("%-32s string=MISSING\n", selectors[i].name);
            continue;
        }

        bool found = false;
        for (uint64_t cursor = selector_refs_start; cursor + sizeof(uint64_t) <= selector_refs_end; cursor += sizeof(uint64_t)) {
            uint64_t pointer = 0;
            memcpy(&pointer, data + cursor, sizeof(pointer));
            if ((uint32_t) pointer == (uint32_t) string_address) {
                uint64_t selector_ref_address = 0;
                file_offset_to_vm_address(data, stat_buffer.st_size, cursor, &selector_ref_address);
                printf("%-32s selref=0x%llx\n", selectors[i].name, selector_ref_address);
                found = true;
            }
        }
        if (!found) printf("%-32s selref=MISSING\n", selectors[i].name);
    }

    munmap(data, stat_buffer.st_size);
    close(fd);
    return EXIT_SUCCESS;
}
