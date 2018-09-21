//int mode = 1;
//int mode1 = 1;
//int mode2 = 1;
//int mode3 = 1;
//char mode4[] = "ABCDEFGHABCDEFGH";
//int mode5 = 1;
//char KEY[] = "SUPERSECRETKEYSUPERSECRETKEYSUPERSECRETKEYSUPERSECRETKEYSUPERSECRETKEY";

struct Foo {
    char KEY[64];
    char mode[8];
};

struct Foo KEY = { .KEY = "SUPERSECRETKEYSUPERSECRETKEYSUPERSECRETKEY", .mode = "ULTRA" };
struct Foo BAR = { .KEY = "SUPERSECRETKEY", .mode = "ULTRA" };


int do_heap();
int do_stack();
int do_global();
