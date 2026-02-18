#include <stdio.h>

int raze_io_validate_input_path(const char *path) {
    FILE *file;

    if (path == 0) {
        return 0;
    }

    file = fopen(path, "rb");
    if (file == 0) {
        return 0;
    }

    fclose(file);
    return 1;
}
