#include <stdio.h>

extern "C" {
    int ICCLoad(void);
    int ICCUnload(void);
/* This is VERY dubious being the C++ destructor
   we may have to link as C++ instead
*/   
void __dl__FPv(void *targ)
{

}

};

class DLL_Load_Init {
  public:
    DLL_Load_Init() {
     /* printf("*******************Loading DLL!\n"); */
      ICCLoad();
    }
    ~DLL_Load_Init() {
      /* printf("Unloading DLL!******************\n"); */
      ICCUnload();
    }
};

static DLL_Load_Init dllLoadInitVar;
