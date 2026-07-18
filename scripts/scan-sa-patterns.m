#import <Foundation/Foundation.h>

#include <errno.h>
#include <fcntl.h>
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
    uint32_t string_offset;
};

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
        { "dock_spaces", get_dock_spaces_offset, get_dock_spaces_pattern },
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
        { "_handleEvent:", 0x35e108 },
        { "addSpace:forDisplayUUID:", 0x3623a4 },
        { "doBindingCommand:display:", 0x364c37 },
        { "moveSpace:toDisplay:displayUUID:", 0x36a4b9 },
        { "removeSpace:", 0x36bb98 },
    };
    const uint64_t selector_refs_start = 0x3e3570;
    const uint64_t selector_refs_end = 0x3e8df0;

    printf("Objective-C selector references\n");
    for (size_t i = 0; i < sizeof(selectors) / sizeof(selectors[0]); ++i) {
        bool found = false;
        for (uint64_t cursor = selector_refs_start; cursor + sizeof(uint64_t) <= selector_refs_end; cursor += sizeof(uint64_t)) {
            uint64_t pointer = 0;
            memcpy(&pointer, data + cursor, sizeof(pointer));
            if ((uint32_t) pointer == selectors[i].string_offset) {
                printf("%-32s selref=0x%llx\n", selectors[i].name, 0x100000000ULL + cursor);
                found = true;
            }
        }
        if (!found) printf("%-32s selref=MISSING\n", selectors[i].name);
    }

    munmap(data, stat_buffer.st_size);
    close(fd);
    return EXIT_SUCCESS;
}
