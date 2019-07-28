#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <ctype.h>

#pragma warn -8060

#define DEBUG 0

#define T printf("%d\n", __LINE__);

#if DEBUG
#define DEBUG_PARAM , int lineno
#define ERROREXIT(a,b) ErrorExit(a,b,__LINE__)
#else
#define DEBUG_PARAM
#define ERROREXIT(a,b) ErrorExit(a,b)
#endif

#define GetMax(a, b) ((a)>(b)?a:b)
#define GetMin(a, b) ((a)<(b)?a:b)
#define IsNameChar(c) ('A'<=c&&c<='Z'||'a'<=c&&c<='z'||c=='_')
#define IsFirstOctChar(c) ('0'<=c&&c<='3')
#define IsOctChar(c) ('0'<=c&&c<='7')
#define IsNumChar(c) ('0'<=c&&c<='9')
#define OctCharToInt(c) (c&0x7)
#define IsHexChar(c) ('A'<=c&&c<='F'||'a'<=c&&c<='f'||'0'<=c&&c<='9')
#define HexCharToInt(c) ((c>>6&1)*9+(c&0xf))
#define GETEBP ((int(*)(void))memcpy(AllocExecuteMemory(3), "\x89\xe8\xc3", 3))()

#define IsIdentifierCharFirst(c) ('a'<=c&&c<='z'||'A'<=c&&c<='Z'||c=='_'||c=='$')
#define IsIdentifierCharFirstVar(c) ('a'<=c&&c<='z'||'A'<=c&&c<='Z'||c=='_')
#define IsIdentifierChar(c) ('a'<=c&&c<='z'||'A'<=c&&c<='Z'||'0'<=c&&c<='9'||c=='_'||c=='$')
#define IsIdentifierCharVar(c) ('a'<=c&&c<='z'||'A'<=c&&c<='Z'||'0'<=c&&c<='9'||c=='_')
#define IsNumberChar(c) ('0'<=c&&c<='9')
#define IsOperatorChar(c) strchr("+-*/%()~!<>=&^|",c)
#define GetTokenType(c) IsIdentifierCharFirst(c)?TT_IDENTIFIER:IsNumberChar(c)?TT_NUMBER:IsOperatorChar(c)?TT_OPERATOR:TT_UNKNOWN

#define VERSION_STRING "rundllex ver 1.5.0"
#define BUFFER_SIZE    512
#define MAX_STMT_COUNT 32768
#define MAX_ARG_COUNT  64
#define MAX_ALLOC_SIZE 65536
#define HASH_KEY 17
#define POP_INSTRUCTION "ZX\x89\xc4\xff\xe2"
#define GETEBX_INSTRUCTION "\x89\xd8\xc3"
#define SETEBX_INSTRUCTION "\x8b\x5c\x24\x04\xc3"

#define RW_COUNT  5
#define RW_STDOUT "stdout"
#define RW_STDERR "stderr"
#define RW_STDIN  "stdin"
#define RW_SL     "sl"
#define RW_LV     "$_"

typedef int (__stdcall *Win32API)(void);
typedef int (__stdcall *PushInstruction)(void);
typedef void (__stdcall *PopInstruction)(int);
typedef int (*GetEBX)(void);
typedef void (*SetEBX)(int);
typedef int (*Operation1)(int a);
typedef int (*Operation2)(int a, int b);
typedef int (*Operation3)(int a, int b, int c);

typedef enum {
  E_DLL_NOT_FOUND = 1,
  E_API_NOT_FOUND,
  E_UNDEF_VAR,
  E_LABEL_NOT_FOUND,
  E_BLOCK_START_NOT_FOUND,
  E_BLOCK_END_NOT_FOUND,
  E_DLL_NAME_TOO_LONG,
  E_API_NAME_TOO_LONG,
  E_INVALID_VAR_NAME,
  E_INVALID_LABEL,
  E_ILLEGAL_ARGS,
  E_INCORRECT_EXPRESSION,
  E_ARG_TOO_LONG,
  E_ARG_LIST_TOO_LONG,
  E_API_LIST_TOO_LONG,
  E_MEMORY_ALLOC_OVER,
  E_MEMORY_ALLOC_FAILED,
  E_CANNOT_OPEN_FILE,
  E_TOPLEVEL_EXCEPTION,
} ERROR_CODE;

struct LISTNODE_ {
  struct LISTNODE_ *next;
  struct LISTNODE_ *prev;
  char *name;
  int value;
  BOOL isRef;
};
typedef struct LISTNODE_ LISTNODE;

typedef struct {
  LISTNODE *first;
  LISTNODE *last;
  int count;
} LIST;

typedef struct {
  LIST list[HASH_KEY];
  int listCount;
  int totalCount;
} HASHTABLE;

typedef struct {
  char **data;
  int *size;
  int cur;
  BOOL *runTrace;
  char ***strTable;
  int *strCount;
  int isReturn;
  int ebp;
  int contextIndex;
  int reeval;
} HEAP;

typedef struct {
  char *stmtBuff;
  char *dllName;
  char *apiName;
  char *refName;
  Win32API *api;
  PushInstruction pushArgs;
} INVOKER;

typedef struct {
  char name[BUFFER_SIZE];
  BOOL dereference;
  char operation[4];
} VAR_ACCESS_DATA;

typedef struct {
  BOOL allowVar;
  BOOL allowAlloc;
  BOOL allowRef;
  BOOL allowImm;
  BOOL allowStr;
  BOOL allowExp;
} ANALYSIS_METHOD;

typedef struct {
  char *name;
  char **stmtList;
  int stmtCount;
  HEAP *heap;
  INVOKER *invoker;
} CONTEXT_DATA;

enum {
  TT_UNDEF,
  TT_NUMBER,
  TT_IDENTIFIER,
  TT_OPERATOR,
  TT_UNKNOWN,
};

typedef struct {
  char *text;
  int type;
  void *ext;
} TOKEN;

typedef struct {
  int base;
} NUMBER_INFO;

typedef struct {
  int priority;
  int operandCount;
  void *operation;
} OPERATOR_INFO;

char const *g_dllList[] = {
    "user32", "kernel32", "shell32", "crtdll", "winmm", "gdi32", "sfc", "wsock32",
    "ole32", "comctl32", "netapi32", "comdlg32", "advapi32","Imm32", "winspool.drv",
    "shlwapi", "version", "setupapi", "UxTheme", "icmp", "imagehlp", "msvcrt"
};
char const *g_allDll = "*";
char const *g_scriptExtList[] = { "rdx", "bat" };

CONTEXT_DATA **g_contextList;
int g_contextCount;
int g_retValue;
int g_end;
char *g_lastErrorStr;
int g_tlsIndex_Heap;
int g_tlsIndex_HeapCur;
int g_tlsIndex_Invoker;
int g_tlsIndex_LastValue;
int g_tlsIndex_ContextIndex;

PopInstruction g_popInstruction;
GetEBX g_getEBX;
SetEBX g_setEBX;

int OpeDereference(int a)         { return *(int*)a; }
int OpeUnaryPlus(int a)           { return a; }
int OpeUnaryMinus(int a)          { return -a; }
int OpeUnaryBitNot(int a)         { return ~a; }
int OpeUnaryNot(int a)            { return !a; }
int OpeMulti(int a, int b)        { return a * b; }
int OpeDiv(int a, int b)          { return a / b; }
int OpeMod(int a, int b)          { return a % b; }
int OpePlus(int a, int b)         { return a + b; }
int OpeMinus(int a, int b)        { return a - b; }
int OpeLeftShift(int a, int b)    { return a << b; }
int OpeRightShift(int a, int b)   { return a >> b; }
int OpeLess(int a, int b)         { return a < b; }
int OpeLessEqual(int a, int b)    { return a <= b; }
int OpeGreater(int a, int b)      { return a > b; }
int OpeGreaterEqual(int a, int b) { return a >= b; }
int OpeEqual(int a, int b)        { return a == b; }
int OpeNotEqual(int a, int b)     { return a != b; }
int OpeBitAnd(int a, int b)       { return a & b; }
int OpeBitXor(int a, int b)       { return a ^ b; }
int OpeBitOr(int a, int b)        { return a | b; }
int OpeAnd(int a, int b)          { return a && b; }
int OpeOr(int a, int b)           { return a || b; }

unsigned *_beginthreadex(void *security, unsigned stack_size, LPTHREAD_START_ROUTINE start_address, void *arglist, unsigned initflag, unsigned *thrdaddr);
WINBASEAPI LONG WINAPI OrgUnhandledExceptionFilter(IN struct _EXCEPTION_POINTERS *ExceptionInfo);
void InitMnemonicFunc(void);
int __stdcall MainLoop(void);
char **LoadStmtList(char *filename, int *stmtCountResult);
int LoadScript(char *filename);
void RegisterReservedWords(void);
BOOL CheckReservedWords(char *name);
void ErrorExit(int eCode, void *param DEBUG_PARAM);
void SetStrLocale(void);
HEAP *GetHeap(void);
void *AllocExecuteMemory(int size);
INVOKER *GetInvoker(void);
HASHTABLE *GetVarTable(void);
void CommitLastValue(int index);
int RunNext(HEAP *heap, int prevIndex);
void InitHeap(HEAP *heap);
void ExtendHeap(HEAP *heap, int extendSize);
void DetermineHeap(HEAP *heap);
char *RegisterStr(HEAP *heap, char *str, int length);
void DumpCurData(HEAP *heap);
void DumpVarTable(void);
BOOL GuessStrValue(LISTNODE *listNode);
int gethash(char *name);
int CheckVarName(char *name);
void SetVar(char *name, int value, BOOL isRef, BOOL freeName);
int GetVar(char *name);
LISTNODE *GetVarNode(char *name);
char *GetVarName(char **str);
char *strrvs(char *dst, char *src);
char *strtokex(char **src, char *delims);
int strtolex(char **str, char **endptr, BOOL parseVar);
BOOL CheckOption(HEAP *heap, INVOKER *invoker);
void DefineFunc(HEAP *heap);
void EndDefineFunc(HEAP *heap);
void ReturnFunc(HEAP *heap, INVOKER *invoker);
void DefineThreadFunc(HEAP *heap);
void EndDefineThreadFunc(HEAP *heap);
void BeginIfBlock(HEAP *heap, INVOKER *invoker);
void CheckElseBlock(HEAP *heap, INVOKER *invoker);
void BeginWhileBlock(HEAP *heap, INVOKER *invoker);
void LoopWhileBlock(HEAP *heap);
void ShowVersion(void);
void ShowHelp(void);
void OperationCmd(HEAP *heap, INVOKER *invoker);
void ModificationCmd(HEAP *heap, INVOKER *invoker);
char *ParseOperationExp(char *expression, int *operand, HEAP *heap);
int DoOperation(int *operand, char *operation);
void ChangeRunIndex(HEAP *heap, char *label);
void ChangeRunIndexToBlockStart(HEAP *heap, char *blockStartStr);
void ChangeRunIndexToBlockEnd(HEAP *heap, char *blockEndStr);
int SearchElseBlock(HEAP *heap);
void GetTargetName(char *arg, INVOKER *invoker);
int IsEllipsisDllName(INVOKER *invoker);
void DecisionFirstArgType(INVOKER *invoker);
BOOL SetAPIAddress(HEAP *heap, INVOKER *invoker);
void CreateAPIArgs(HEAP *heap, INVOKER *invoker);
int GetArgValue(char **arg, HEAP *heap, ANALYSIS_METHOD *am, char *delims);
int GetAllocArgValue(char **arg, HEAP *heap);
int GetRefArgValue(char **arg, HEAP *heap);
int GetExpArgValue(char **arg);
int GetImmArgValue(char **arg, HEAP *heap, char **estr, char *delims);
int ConvertStr(char *arg, char *buff);
int GetIndex(char **arg, int cur, char *delims);
void CreatePushInstruction(char *pushArgs, int *stmts, int stmtCount);
void CallAPI(HEAP *heap, INVOKER *invoker);
void slmain(void);
TOKEN **GetTokenList(char *srcText, int *retCount);
TOKEN *GetToken(char *textStart, char *textEnd, int tokenType, void *ext);
int EvalExp(char *src);
int OperationTokenList(TOKEN **tokenList, int tokenCount, int *cur);

int main(int argc, char *argv[])
{
  int i, length;
  char **stmtList = (char**)malloc(MAX_STMT_COUNT * sizeof(char*));

  if (argc == 1) return 0;
  if (argc - 1 > MAX_STMT_COUNT) ERROREXIT(E_API_LIST_TOO_LONG, NULL);
  SetUnhandledExceptionFilter(OrgUnhandledExceptionFilter);
  SetStrLocale();
  InitMnemonicFunc();

  g_contextList = (CONTEXT_DATA**)malloc(sizeof(CONTEXT_DATA*));
  g_contextList[0] = (CONTEXT_DATA*)calloc(1, sizeof(CONTEXT_DATA));
  g_contextCount = 1;
  for (i = 1; i < argc; ++i) {
    length = strlen(argv[i]);
    if (length > BUFFER_SIZE - 1) ERROREXIT(E_ARG_TOO_LONG, (void*)(i - 1));
    stmtList[i - 1] = (char*)malloc((length + 1) * sizeof(char*));
    strcpy(stmtList[i - 1], argv[i]);
  }
  g_contextList[0]->name = "";
  g_contextList[0]->stmtList = (char**)realloc(stmtList, --argc * sizeof(char*));
  g_contextList[0]->stmtCount = argc;

  RegisterReservedWords();
  g_lastErrorStr = malloc(1024);
  g_tlsIndex_Heap = TlsAlloc();
  g_tlsIndex_HeapCur = TlsAlloc();
  g_tlsIndex_Invoker = TlsAlloc();
  g_tlsIndex_LastValue = TlsAlloc();
  g_tlsIndex_ContextIndex = TlsAlloc();

  TlsSetValue(g_tlsIndex_ContextIndex, 0);

  g_retValue = MainLoop();
  g_end = 1;

  /* Win7(64bit)環境ではmainからのreturnで固まることがあるためexit */
  exit(g_retValue);

  return 0;
}

WINBASEAPI LONG WINAPI OrgUnhandledExceptionFilter(IN struct _EXCEPTION_POINTERS *exceptionInfo)
{
  if (g_end) exit(g_retValue);

  switch (exceptionInfo->ExceptionRecord->ExceptionCode) {
#define CreateCase(c) case c: ERROREXIT(E_TOPLEVEL_EXCEPTION, #c);
  CreateCase(EXCEPTION_ACCESS_VIOLATION)
  CreateCase(EXCEPTION_BREAKPOINT)
  CreateCase(EXCEPTION_DATATYPE_MISALIGNMENT)
  CreateCase(EXCEPTION_SINGLE_STEP)
  CreateCase(EXCEPTION_ARRAY_BOUNDS_EXCEEDED)
  CreateCase(EXCEPTION_FLT_DENORMAL_OPERAND)
  CreateCase(EXCEPTION_FLT_DIVIDE_BY_ZERO)
  CreateCase(EXCEPTION_FLT_INEXACT_RESULT)
  CreateCase(EXCEPTION_FLT_INVALID_OPERATION)
  CreateCase(EXCEPTION_FLT_OVERFLOW)
  CreateCase(EXCEPTION_FLT_STACK_CHECK)
  CreateCase(EXCEPTION_FLT_UNDERFLOW)
  CreateCase(EXCEPTION_INT_DIVIDE_BY_ZERO)
  CreateCase(EXCEPTION_INT_OVERFLOW)
  CreateCase(EXCEPTION_PRIV_INSTRUCTION)
  CreateCase(EXCEPTION_NONCONTINUABLE_EXCEPTION)
#undef CreateCase
  }

  return EXCEPTION_EXECUTE_HANDLER;
}

void InitMnemonicFunc(void)
{
  int popInstructionSize = strlen(POP_INSTRUCTION);
  int getEBXSize = strlen(GETEBX_INSTRUCTION);
  int setEBXSize = strlen(SETEBX_INSTRUCTION);

  g_popInstruction = (PopInstruction)memcpy(AllocExecuteMemory(popInstructionSize), POP_INSTRUCTION, popInstructionSize);
  g_getEBX = (GetEBX)memcpy(AllocExecuteMemory(getEBXSize), GETEBX_INSTRUCTION, getEBXSize);
  g_setEBX = (SetEBX)memcpy(AllocExecuteMemory(setEBXSize), SETEBX_INSTRUCTION, setEBXSize);
}

int __stdcall MainLoop(void)
{
  int prevIndex, stmtCount;
  HEAP *heap, orgHeap;
  INVOKER *invoker, orgInvoker;
  char strtokBuff[BUFFER_SIZE];

  heap    = GetHeap();
  invoker = GetInvoker();
  memcpy(&orgHeap, heap, sizeof(HEAP));
  memcpy(&orgInvoker, invoker, sizeof(INVOKER));
  heap->cur = (int)TlsGetValue(g_tlsIndex_HeapCur);
  heap->contextIndex = (int)TlsGetValue(g_tlsIndex_ContextIndex);
  heap->ebp = GETEBP + 8;
  stmtCount = g_contextList[heap->contextIndex]->stmtCount;
  for (prevIndex = heap->cur; heap->cur < stmtCount; prevIndex = RunNext(heap, prevIndex)) {
    invoker->stmtBuff = strtokBuff;
    InitHeap(heap);
    GetTargetName(g_contextList[heap->contextIndex]->stmtList[heap->cur], invoker);
    if (CheckOption(heap, invoker) == TRUE) continue;
    if (heap->isReturn) break;
    DecisionFirstArgType(invoker);
    if (SetAPIAddress(heap, invoker)) {
      strcpy(invoker->stmtBuff, g_contextList[heap->contextIndex]->stmtList[heap->cur]);
      strtokex(&invoker->stmtBuff, ",");
    }
    CreateAPIArgs(heap, invoker);
    CallAPI(heap, invoker);
  }
  memcpy(heap, &orgHeap, sizeof(HEAP));
  memcpy(invoker, &orgInvoker, sizeof(INVOKER));
  TlsSetValue(g_tlsIndex_HeapCur, (void*)heap->cur);
  TlsSetValue(g_tlsIndex_ContextIndex, (void*)heap->contextIndex);
  if (heap->cur < stmtCount) return (int)TlsGetValue(g_tlsIndex_LastValue);
  return 0;
}

char **LoadStmtList(char *filename, int *stmtCountResult)
{
  char **stmtList = (char**)malloc(MAX_STMT_COUNT * sizeof(char*));
  char buff[BUFFER_SIZE], *pBuff;
  int length;
  int stmtCount = 0;
  FILE *fp;

  fp = fopen(filename, "r");

  if (fp == NULL) ERROREXIT(E_CANNOT_OPEN_FILE, filename);
  while (fgets(buff, BUFFER_SIZE, fp)) {
    if (*buff == '\0' || *buff == '@' || *buff == '\n') continue;
    if (*buff == ':') break;
    pBuff = buff;
    if (stmtCount == MAX_STMT_COUNT) ERROREXIT(E_API_LIST_TOO_LONG, NULL);
    while (*pBuff == ' ' || *pBuff == '\t') ++pBuff;
    length = strlen(pBuff);
    if (pBuff[length - 1] == '\n') {
      if (length == BUFFER_SIZE - 1) {
        ERROREXIT(E_ARG_TOO_LONG, (void*)stmtCount);
      } else {
        --length;
      }
    }
    stmtList[stmtCount] = (char*)calloc(length + 1, 1);
    strncpy(stmtList[stmtCount++], pBuff, length);
  }

  fclose(fp);

  stmtList = (char**)realloc(stmtList, stmtCount * sizeof(char*));
  *stmtCountResult = stmtCount;
  return stmtList;
}

int LoadScript(char *filename)
{
  char buff[BUFFER_SIZE], **stmtList;
  int extListCount = sizeof(g_scriptExtList) / sizeof(char*), i, stmtCount, offset = 0;
  unsigned char *func;

  for (i = 0; i < extListCount; ++i) {
    sprintf(buff, "%s.%s", filename, g_scriptExtList[i]);
    if (GetFileAttributes(buff) != 0xffffffff) break;
  }
  if (i == extListCount) return 0;

  stmtList = LoadStmtList(buff, &stmtCount);
  g_contextList = realloc(g_contextList, (g_contextCount + 1) * sizeof(CONTEXT_DATA*));
  g_contextList[g_contextCount] = calloc(1, sizeof(CONTEXT_DATA));
  g_contextList[g_contextCount]->name = strcpy(malloc(strlen(filename)+1), filename);
  g_contextList[g_contextCount]->stmtList = stmtList;
  g_contextList[g_contextCount]->stmtCount = stmtCount;

  func = AllocExecuteMemory(32);
  func[offset++] = 0xbb; /* mov ebx */
  *((int*)&func[(offset+=4)-4]) = (int)TlsSetValue;
  func[offset++] = 0x68; /* push DWORD */
  *((int*)&func[(offset+=4)-4]) = g_contextCount++;
  func[offset++] = 0x68; /* push DWORD */
  *((int*)&func[(offset+=4)-4]) = g_tlsIndex_ContextIndex;
  func[offset++] = 0xff; /* call EBX */
  func[offset++] = 0xd3;
  func[offset++] = 0xbb; /* mov ebx */
  *((int*)&func[(offset+=4)-4]) = (int)MainLoop;
  func[offset++] = 0xff; /* jmp ebx */
  func[offset]   = 0xe3;

  return (int)func;
}

void RegisterReservedWords(void)
{
  SetVar(RW_STDOUT, (int)stdout, FALSE, TRUE);
  SetVar(RW_STDERR, (int)stderr, FALSE, TRUE);
  SetVar(RW_STDIN,  (int)stdin,  FALSE, TRUE);
  SetVar(RW_SL,     (int)slmain, FALSE, TRUE);
}

BOOL CheckReservedWords(char *name)
{
  if (!strcmp(name, RW_STDOUT)
  ||  !strcmp(name, RW_STDERR)
  ||  !strcmp(name, RW_STDIN)
  ||  !strcmp(name, RW_SL)
  ||  !strcmp(name, RW_LV)) {
    return TRUE;
  }
  return FALSE;
}

void ErrorExit(int eCode, void *param DEBUG_PARAM)
{
  BOOL printRunIndex = TRUE;
  HEAP *heap = GetHeap();
#if DEBUG
printf("%d ", lineno);
#endif
  fprintf(stderr, "Error 0x%04x: ", eCode);
  switch (eCode) {
  case E_DLL_NOT_FOUND:
    fprintf(stderr, "DLL not found [%s]\n", param);
    break;
  case E_API_NOT_FOUND:
    fprintf(stderr, "API not found [%s]\n", param);
    break;
  case E_UNDEF_VAR:
    fprintf(stderr, "Undefined variable [%s]\n", param);
    break;
  case E_LABEL_NOT_FOUND:
    fprintf(stderr, "Label not found [%s]\n", param);
    break;
  case E_BLOCK_START_NOT_FOUND:
    fprintf(stderr, "Block Start not found [%s]\n", param);
    break;
  case E_BLOCK_END_NOT_FOUND:
    fprintf(stderr, "Block End not found [%s]\n", param);
    break;
  case E_DLL_NAME_TOO_LONG:
    fprintf(stderr, "DLL name too long [%s]\n", param);
    break;
  case E_API_NAME_TOO_LONG:
    fprintf(stderr, "API name too long [%s]\n", param);
    break;
  case E_INVALID_VAR_NAME:
    fprintf(stderr, "Invalid variable name\n");
    break;
  case E_INVALID_LABEL:
    fprintf(stderr, "Invalid label\n");
    break;
  case E_ILLEGAL_ARGS:
    fprintf(stderr, "Illegal arguments\n");
    break;
  case E_INCORRECT_EXPRESSION:
    fprintf(stderr, "Incorrect expression\n");
    break;
  case E_ARG_TOO_LONG:
    fprintf(stderr, "Argument too long (buffer size: %dbyte) [index=%d]\n", BUFFER_SIZE - 1, param);
    printRunIndex = FALSE;
    break;
  case E_ARG_LIST_TOO_LONG:
    fprintf(stderr, "Argument list too long [max=%d]\n", MAX_ARG_COUNT);
    printRunIndex = FALSE;
    break;
  case E_API_LIST_TOO_LONG:
    fprintf(stderr, "API list too long [max=%d]\n", MAX_STMT_COUNT);
    printRunIndex = FALSE;
    break;
  case E_MEMORY_ALLOC_OVER:
    fprintf(stderr, "Memory allocation size exceeds the limit (max:%dbyte)\n", MAX_ALLOC_SIZE - 4);
    break;
  case E_MEMORY_ALLOC_FAILED:
    fprintf(stderr, "Memory allocation failed\n");
    break;
  case E_CANNOT_OPEN_FILE:
    fprintf(stderr, "Can't open file [%s]\n", param);
    break;
  case E_TOPLEVEL_EXCEPTION:
    fprintf(stderr, "Exception [%s]\n", param);
    break;
  }
  if (printRunIndex == TRUE) {
    if (*g_contextList[heap->contextIndex]->name) fprintf(stderr, "<< %s >>\n", g_contextList[heap->contextIndex]->name);
    fprintf(stderr, "  index = %d", heap->cur);
    fprintf(stderr, " [%s]", g_contextList[heap->contextIndex]->stmtList[heap->cur]);
    fputs("\n", stderr);
  }

  exit(1);
}

void SetStrLocale(void)
{
  char buff[32];

  GetLocaleInfo(GetUserDefaultLCID(), LOCALE_SENGLANGUAGE, buff, 32);
  if (!strcmp(buff, "Japanese")) setlocale(LC_CTYPE, "jpn");
}

HEAP *GetHeap(void)
{
  HEAP *heap, *threadHeap;
  int i, contextIndex = (int)TlsGetValue(g_tlsIndex_ContextIndex), stmtCount;

  heap = g_contextList[contextIndex]->heap;
  if (heap == NULL) {
    stmtCount = g_contextList[contextIndex]->stmtCount;
    heap = (HEAP*)malloc(sizeof(HEAP));
    heap->data = (char**)malloc(stmtCount * sizeof(char*));
    heap->size = (int*)calloc(stmtCount, sizeof(int));
    heap->strTable = (char***)malloc(stmtCount * sizeof(char**));
    for (i = 0; i < stmtCount; ++i) {
      heap->strTable[i] = (char**)malloc((MAX_ARG_COUNT + 1) * sizeof(char*));
    }
    heap->strCount = (int*)calloc(stmtCount, sizeof(int));
    heap->runTrace = (int*)calloc(stmtCount, sizeof(BOOL));
    heap->reeval = 0;
    g_contextList[contextIndex]->heap = heap;
    TlsSetValue(g_tlsIndex_Heap, 0);
  }

  threadHeap = (HEAP*)TlsGetValue(g_tlsIndex_Heap);
  if (!threadHeap) {
    threadHeap = (HEAP*)malloc(sizeof(HEAP));
    *threadHeap = *heap;
    threadHeap->isReturn = 0;
    TlsSetValue(g_tlsIndex_Heap, threadHeap);
  }

  return threadHeap;
}

void *AllocExecuteMemory(int size)
{
  void *allocatedMemory;
  DWORD lpflOldProtect;
  BOOL result;

  allocatedMemory = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
  if (allocatedMemory == NULL) ERROREXIT(E_MEMORY_ALLOC_FAILED, NULL);
  result = VirtualProtect(allocatedMemory, size, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
  if (result == FALSE) ERROREXIT(E_MEMORY_ALLOC_FAILED, NULL);

  return allocatedMemory;
}

INVOKER *GetInvoker(void)
{
  INVOKER *invoker, *threadInvoker;
  int contextIndex = (int)TlsGetValue(g_tlsIndex_ContextIndex);
  int stmtCount = g_contextList[contextIndex]->stmtCount;

  invoker = g_contextList[contextIndex]->invoker;
  if (invoker == NULL) {
    invoker = (INVOKER*)malloc(sizeof(INVOKER));
    invoker->api      = (Win32API*)AllocExecuteMemory(stmtCount * sizeof(Win32API));
    invoker->pushArgs = (PushInstruction)AllocExecuteMemory(BUFFER_SIZE);
    g_contextList[contextIndex]->invoker = invoker;
    TlsSetValue(g_tlsIndex_Invoker, 0);
  }

  threadInvoker = (INVOKER*)TlsGetValue(g_tlsIndex_Invoker);
  if (!threadInvoker) {
    threadInvoker = (INVOKER*)malloc(sizeof(INVOKER));
    *threadInvoker = *invoker;
    TlsSetValue(g_tlsIndex_Invoker, threadInvoker);
  }

  return threadInvoker;
}

HASHTABLE *GetVarTable(void)
{
  static HASHTABLE *varTable = NULL;
  int i;

  if (varTable == NULL) {
    varTable = (HASHTABLE*)malloc(sizeof(HASHTABLE));
    varTable->listCount = HASH_KEY;
    varTable->totalCount = 0;
    for (i = 0; i < varTable->listCount; ++i) {
      varTable->list[i].first = varTable->list[i].last = NULL;
      varTable->list[i].count = 0;
    }
  }

  return varTable;
}

void CommitLastValue(int index)
{
  HEAP *heap = GetHeap();
  char *refName = GetInvoker()->refName;
  int lastValue = *(int*)&heap->data[index][heap->size[index] - 4];
  TlsSetValue(g_tlsIndex_LastValue, (void*)lastValue);
  if (refName) SetVar(refName, lastValue, FALSE, FALSE);
}

int RunNext(HEAP *heap, int prevIndex)
{
  if (heap->size[prevIndex] >= 4) CommitLastValue(prevIndex);

  heap->runTrace[prevIndex] = TRUE;
  ++heap->cur;

  return heap->cur;
}

void InitHeap(HEAP *heap)
{
  if (heap->runTrace[heap->cur] == FALSE) {
    heap->data[heap->cur] = (char*)malloc(MAX_ALLOC_SIZE);
  }
  heap->size[heap->cur] = 0;
  heap->strCount[heap->cur] = 0;
}

void ExtendHeap(HEAP *heap, int extendSize)
{
  heap->size[heap->cur] += extendSize;
  if (heap->size[heap->cur] > MAX_ALLOC_SIZE) ERROREXIT(E_MEMORY_ALLOC_OVER, NULL);
}

void DetermineHeap(HEAP *heap)
{
  DWORD lpflOldProtect;

  if (heap->runTrace[heap->cur] == FALSE) {
    if (heap->cur >= 0 && heap->size[heap->cur] > 0) {
      heap->data[heap->cur] = (char*)realloc(heap->data[heap->cur], heap->size[heap->cur]);
      VirtualProtect(heap->data[heap->cur], heap->size[heap->cur], PAGE_EXECUTE_READWRITE, &lpflOldProtect);
    } else {
      free(heap->data[heap->cur]);
    }
  }
}

char *RegisterStr(HEAP *heap, char *str, int length)
{
  char *alloc;
  DWORD lpflOldProtect;

  ++heap->strCount[heap->cur];
  if (heap->runTrace[heap->cur] == TRUE) {
    return heap->strTable[heap->cur][heap->strCount[heap->cur]-1];
  }

  alloc = (char*)malloc(length+1);
  heap->strTable[heap->cur][heap->strCount[heap->cur]-1] = alloc;
  memcpy(alloc, str, length+1);
  VirtualProtect(alloc, length+1, PAGE_EXECUTE_READWRITE, &lpflOldProtect);

  return alloc;
}

void DumpCurData(HEAP *heap)
{
  int i, j, k;
  char dumpByteCount;
  char dumpStrBuff[20];

  puts("*********** memory dump ***********");
  if (*g_contextList[heap->contextIndex]->name) printf("<< %s >>\n", g_contextList[heap->contextIndex]->name);
  for (i = 0; i < heap->cur; ++i) {
    if (heap->size[i] <= 0) continue;
    printf("%d: [%s]\n", i, g_contextList[heap->contextIndex]->stmtList[i]);
    for (j = 0; j < heap->size[i]; j += 16) {
      dumpByteCount = GetMin(16, heap->size[i] - j);
      memcpy(dumpStrBuff, heap->data[i] + j, dumpByteCount);
      for (k = 0; k < dumpByteCount; ++k) {
        if (0 <= dumpStrBuff[k] && dumpStrBuff[k] <= 31) dumpStrBuff[k] = '.';
      }
      dumpStrBuff[k] = '\0';
      printf("  %04X: ", j);
      for (k = 0; k < dumpByteCount; ++k) {
        printf("%s%02X ",  k == 8 ? "- " : "", (unsigned char)heap->data[i][j+k]);
      }
      if (k <= 8) printf("  ");
      while (k++ < 16) printf("   ");
      printf("   %s\n", dumpStrBuff);
    }
  }
  DumpVarTable();
  puts("***********************************\n");
}

void DumpVarTable(void)
{
  HASHTABLE *varTable = GetVarTable();
  LISTNODE *listNode;
  int i;

  if (varTable->totalCount <= RW_COUNT) return;

  puts("********** variable dump **********");
  for (i = 0; i < varTable->listCount; ++i) {
    for (listNode = varTable->list[i].first; listNode != NULL; listNode = listNode->next) {
      if (CheckReservedWords(listNode->name) == TRUE) continue;
      printf("%s = %d", listNode->name, listNode->value);
      if (GuessStrValue(listNode) == TRUE) printf(", '%s'", listNode->value);
      puts("");
    }
  }
}

BOOL GuessStrValue(LISTNODE *listNode)
{
  HEAP *heap = GetHeap();
  int value = listNode->value;
  int heapTerm = (int)&heap->data[heap->cur][heap->size[heap->cur] - 4];

  if ((int)heap->data[0] <= value && value <= heapTerm) return TRUE;
  if (listNode->isRef == FALSE) return FALSE;

  return !IsBadCodePtr((FARPROC)value);
}

int gethash(char *name)
{
  return *name % HASH_KEY;
}

int CheckVarName(char *name)
{
  if (!IsIdentifierCharFirstVar(*name)) return 0;
  while (*++name) if (!IsIdentifierCharVar(*name)) return 0;
  return 1;
}

void SetVar(char *name, int value, BOOL isRef, BOOL freeName)
{
  HASHTABLE *varTable = GetVarTable();
  LIST *list = &varTable->list[gethash(name)%varTable->listCount];
  LISTNODE *listNode = GetVarNode(name);

  if (freeName == FALSE && !CheckVarName(name)) ERROREXIT(E_INVALID_VAR_NAME, NULL);
  if (listNode == NULL) {
    listNode = (LISTNODE*)malloc(sizeof(LISTNODE));
    listNode->next  = NULL;
    listNode->prev  = list->last;
    strcpy(listNode->name = (char*)malloc(strlen(name)+1), name);
    if (list->count == 0) list->first      = listNode;
    else                  list->last->next = listNode;
    list->last = listNode;
    ++list->count;
    ++varTable->totalCount;
  }
  listNode->value = value;
  listNode->isRef = isRef;
}

int GetVar(char *name)
{
  LISTNODE *listNode;
  char *endptr;
  int argNum, script;

  if (*name == '$') {
    if (!strcmp(name, "$_")) {
      return (int)TlsGetValue(g_tlsIndex_LastValue);
    } else {
      argNum = strtol(name + 1, &endptr, 10);
      if (*endptr || !argNum) ERROREXIT(E_UNDEF_VAR, name);
      return *((int*)(GetHeap()->ebp + (argNum - 1) * 4));
    }
  } else {
    listNode = GetVarNode(name);
    if (listNode == NULL) {
      script = LoadScript(name);
      if (!script) ERROREXIT(E_UNDEF_VAR, name);
      SetVar(name, script, FALSE, TRUE);
      return script;
    }
    return listNode->value;
  }
}

LISTNODE *GetVarNode(char *name)
{
  HASHTABLE *varTable = GetVarTable();
  LISTNODE *listNode = varTable->list[gethash(name)].first;

  while (listNode != NULL) {
    if (!strcmp(listNode->name, name)) return listNode;
    listNode = listNode->next;
  }

  return NULL;
}

char *GetVarName(char **str)
{
  char *splitPos;

  **str = '\0';
  splitPos = strchr(++*str, '}');
  if (!splitPos) ERROREXIT(E_ILLEGAL_ARGS, NULL);
  *splitPos = '\0';
  splitPos = *str;
  *str += strlen(splitPos) + 1;

  return splitPos;
}

char *strrvs(char *dst, char *src)
{
  char *org_dst = dst, *org_src = src;
  for (src = strchr(src, '\0'), dst[src - org_src] = '\0'; src - org_src; *dst++ = *--src) ;
  return org_dst;
}

char *strtokex(char **src, char *delims)
{
  char *pbegin, *pend;

  pbegin = *src;
  pbegin += strspn(pbegin, delims);
  if (*pbegin == '\0') return NULL;
  pend = pbegin + strcspn(pbegin, delims);
  if (*pend != '\0') *pend++ = '\0';
  *src = pend;
  return pbegin;
}

int strtolex(char **str, char **endptr, BOOL parseVar)
{
  int offset = 0;
  int base = 10;
  int result;
  char *varName;

  if (parseVar == TRUE) varName = **str == '{' ? GetVarName(str) : NULL;

  if (**str == '+' || **str == '-') offset = 1;
  if      (!strncmp(*str + offset, "0x", 2) && *(*str + offset + 2)) base = 16;
  else if (!strncmp(*str + offset, "0",  1))                         base = 8;
  result = (int)strtol(*str, endptr, base);

  if (parseVar == TRUE && varName) SetVar(varName, result, FALSE, FALSE);

  return result;
}

char *strlwr(char *str)
{
  char *src = str--;
  while (*++str) {
    if (isupper(*str)) *str = tolower(*str);
  }
  return src;
}

BOOL CheckOption(HEAP *heap, INVOKER *invoker)
{
  BOOL goNext = TRUE;
  if (invoker->dllName == NULL) return FALSE;

  if (!strcmp(invoker->dllName, "-d")) {
    heap->size[heap->cur] = -1;
    DumpCurData(heap);
  } else if (!strcmp(invoker->dllName, "-f")) {
    DefineFunc(heap);
  } else if (!strcmp(invoker->dllName, "f-")) {
    EndDefineFunc(heap);
    goNext = FALSE;
  } else if (!strcmp(invoker->dllName, "-r")) {
    ReturnFunc(heap, invoker);
    goNext = FALSE;
  } else if (!strcmp(invoker->dllName, "-t")) {
    DefineThreadFunc(heap);
  } else if (!strcmp(invoker->dllName, "t-")) {
    EndDefineThreadFunc(heap);
    goNext = FALSE;
  } else if (!strcmp(invoker->dllName, "-i")) {
    BeginIfBlock(heap, invoker);
  } else if (!strcmp(invoker->dllName, "i-")) {
  } else if (!strcmp(invoker->dllName, "-e")) {
    CheckElseBlock(heap, invoker);
  } else if (!strcmp(invoker->dllName, "-w")) {
    BeginWhileBlock(heap, invoker);
  } else if (!strcmp(invoker->dllName, "w-")) {
    LoopWhileBlock(heap);
  } else if (!strcmp(invoker->dllName, "-v")) {
    if (heap->cur != 0) ERROREXIT(E_ILLEGAL_ARGS, NULL);
    ShowVersion();
  } else if (!strcmp(invoker->dllName, "-h")) {
    if (heap->cur != 0) ERROREXIT(E_ILLEGAL_ARGS, NULL);
    ShowHelp();
  } else if (!strcmp(invoker->dllName, "/?")) {
    if (heap->cur != 0) ERROREXIT(E_ILLEGAL_ARGS, NULL);
    ShowHelp();
  } else if (!strncmp(invoker->dllName, "-o", 2)) {
    OperationCmd(heap, invoker);
  } else if (!strncmp(invoker->dllName, "-m", 2)) {
    ModificationCmd(heap, invoker);
  } else {
    return FALSE;
  }

  DetermineHeap(heap);
  return goNext;
}

void DefineFunc(HEAP *heap)
{
  unsigned char *func;
  int offset = 0;

  ExtendHeap(heap, 4);
  if (heap->runTrace[heap->cur] == FALSE) {
    func = AllocExecuteMemory(32);
    func[offset++] = 0xbb; /* mov ebx */
    *((int*)&func[(offset+=4)-4]) = (int)TlsSetValue;
    func[offset++] = 0x68; /* push DWORD */
    *((int*)&func[(offset+=4)-4]) = heap->cur + 1;
    func[offset++] = 0x68; /* push DWORD */
    *((int*)&func[(offset+=4)-4]) = g_tlsIndex_HeapCur;
    func[offset++] = 0xff; /* call EBX */
    func[offset++] = 0xd3;
    func[offset++] = 0xbb; /* mov ebx */
    *((int*)&func[(offset+=4)-4]) = (int)MainLoop;
    func[offset++] = 0xff; /* jmp ebx */
    func[offset]   = 0xe3;
    *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] = (int)func;
  }
  ChangeRunIndexToBlockEnd(heap, "f-");
  heap->size[heap->cur] = -1;
}

void EndDefineFunc(HEAP *heap)
{
  heap->isReturn = 1;
}

void ReturnFunc(HEAP *heap, INVOKER *invoker)
{
  ANALYSIS_METHOD am = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };

  heap->isReturn = 1;
  ExtendHeap(heap, 4);
  *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] = GetArgValue(&invoker->apiName, heap, &am, "");
  CommitLastValue(heap->cur);
}

void DefineThreadFunc(HEAP *heap)
{
  unsigned char *func;
  int offset = 0;

  ExtendHeap(heap, 8);
  if (heap->runTrace[heap->cur] == FALSE) {
    func = AllocExecuteMemory(32);
    func[offset++] = 0xbb; /* mov ebx */
    *((int*)&func[(offset+=4)-4]) = (int)TlsSetValue;
    func[offset++] = 0x68; /* push DWORD */
    *((int*)&func[(offset+=4)-4]) = heap->cur + 1;
    func[offset++] = 0x68; /* push DWORD */
    *((int*)&func[(offset+=4)-4]) = g_tlsIndex_HeapCur;
    func[offset++] = 0xff; /* call EBX */
    func[offset++] = 0xd3;
    func[offset++] = 0xbb; /* mov ebx */
    *((int*)&func[(offset+=4)-4]) = (int)MainLoop;
    func[offset++] = 0xff; /* jmp ebx */
    func[offset]   = 0xe3;
    *(int*)&heap->data[heap->cur][heap->size[heap->cur]-8] = (int)func;
  } else {
    func = (unsigned char*)*(int*)&heap->data[heap->cur][heap->size[heap->cur]-8];
  }
  *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] =
    (int)_beginthreadex(NULL, 0, (LPTHREAD_START_ROUTINE)func, NULL, 0, NULL);
  ChangeRunIndexToBlockEnd(heap, "t-");
  heap->size[heap->cur] = -1;
}

void EndDefineThreadFunc(HEAP *heap)
{
  heap->isReturn = 1;
}

void BeginIfBlock(HEAP *heap, INVOKER *invoker)
{
  ANALYSIS_METHOD am = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };
  int result;

  if (invoker->apiName && *invoker->apiName) result = GetArgValue(&invoker->apiName, heap, &am, "");
  else                                       result = 1;
  ExtendHeap(heap, 4);
  *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] = result;
  if (!result) {
    if (SearchElseBlock(heap)) {
      heap->reeval = 1;
    } else {
      ChangeRunIndexToBlockEnd(heap, "i-");
      heap->size[heap->cur] = -1;
    }
  }
}

void CheckElseBlock(HEAP *heap, INVOKER *invoker)
{
  ANALYSIS_METHOD am = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };
  int result;

  if (heap->reeval) {
    heap->reeval = 0;
    if (invoker->apiName && *invoker->apiName) result = GetArgValue(&invoker->apiName, heap, &am, "");
    else                                       result = 1;
    ExtendHeap(heap, 4);
    *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] = result;
    if (!result) {
      if (SearchElseBlock(heap)) {
        heap->reeval = 1;
      } else {
        ChangeRunIndexToBlockEnd(heap, "i-");
        heap->size[heap->cur] = -1;
      }
    }
  } else {
    ChangeRunIndexToBlockEnd(heap, "i-");
    heap->size[heap->cur] = -1;
  }
}

void BeginWhileBlock(HEAP *heap, INVOKER *invoker)
{
  ANALYSIS_METHOD am = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };
  int result;

  if (invoker->apiName && *invoker->apiName) result = GetArgValue(&invoker->apiName, heap, &am, "");
  else                                       result = 1;
  ExtendHeap(heap, 4);
  *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] = result;
  if (!result) {
    ChangeRunIndexToBlockEnd(heap, "w-");
    heap->size[heap->cur] = -1;
  }
}

void LoopWhileBlock(HEAP *heap)
{
  ChangeRunIndexToBlockStart(heap, "-w");
}

void ShowVersion(void)
{
  puts(VERSION_STRING);
  exit(0);
}

void ShowHelp(void)
{
  puts(
    "usage: rundllex [-d] [-v] [-h] [-o<exp[,index]>] [-m<exp[,index]>]\n"
    "                [[DLLname,]APIname[,arg[,...]] [...]]\n\n"
    "    -d          show memory dump\n"
    "    -v          show version\n"
    "    -h (or /?)  show this message\n"
    "    -o          operation command\n"
    "        syntax:operand[<operator><operand>][,<index|label>]\n"
    "            operand     numeric value\n"
    "            operator    supports the following operations\n"
    "                        [+ - * / % | & ^ > < ! ~ == >= <= != << >>]\n"
    "            index       index that jumps when the result is non-zero\n"
    "            label       label that jumps when the result is non-zero\n"
    "    -m          modification command\n"
    "        syntax:target=operand[,<index|label>]\n"
    "            target      dst item(reference)\n"
    "            operand     numeric value\n"
    "    DLLname     target DLL\n"
    "    APIname     called API ('A' is appended if necessary)\n"
    "    arg         API arguments\n\n"
    "extended syntax:\n\n"
    "    [label:][{var}]<DLLname|*>\n"
    "        label        string as a label\n"
    "        var          variable for assigning return value of API\n"
    "        DLLname      target DLL\n"
    "        *            specifier to use default DLL list\n"
    "    [{var}][#|0x]value\n"
    "        var          variable for assigning value\n"
    "        value        numeric value or string value\n"
    "        #            string prifix\n"
    "        0x           hexdecimal prefix\n"
    "    ( [*]allocsize[=initvalue[/...]] )\n"
    "        *            dereference prefix\n"
    "        allocsize    memory allocation size (byte)\n"
    "        initvalue    initialization value (4byte)\n"
    "    [ [*][+|-]<index|var>[.<offset|r>] ]\n"
    "        *            dereference prefix\n"
    "        +/-          relative index prefix\n"
    "        index        index of API list\n"
    "        var          variable name\n"
    "        offset       reference offset (byte)\n"
    "        r            return value of API\n\n"
    "examples:\n\n"
    "    rundllex user32.dll,MessageBox,0,message,title,0\n"
    "    rundllex *,sprintf,(8),#%d,0x11 *,puts,[0]\n"
    "    rundllex *,GetDC,0 *,GetStockObject,3^\n"
    "             *,FillRect,[*-2.r],(16=100/100/200/200),[*1.r]\n"
    "    rundllex *,printf,%d%c,(*8=1/0),10 -o[*0]+[*0.4]^\n"
    "             -m[0.4]=[*0] -m[0]=[*1] \"-o[*0]<=1000,0\"\n"
    "    rundllex *,LoadLibrary,user32 *,GetProcAddress,[*-1],DefWindowProcA^\n"
    "             *,RegisterClass,(40=0/[*-1]/0/0/0/0/0/6/0/R) \"-o1<<31\"^\n"
    "             *,CreateWindowEx,0,R,R,0x10cf0000,[*-1],[*-1],[*-1],[*-1],0,0,0,0^\n"
    "             *,IsWindow,[*-1] \"-o![*-1.r],+8\" *,PeekMessage,(32),0,0,0,1^\n"
    "             \"-o![*-1],+4\" *,TranslateMessage,[-2] *,DispatchMessage,[-3]^\n"
    "             \"-o1,+2\" *,Sleep,1 \"-o1,-8\" *,exit,0\n"
    "    rundllex {hFile}*,CreateFile,sparsefile,0x40000000,0,0,2,0,0^\n"
    "             *,DeviceIoControl,[hFile],590020,0,0,0,0,(4),0^\n"
    "             *,SetFilePointer,[hFile],0x2f900000,(4=0x950),0^\n"
    "             *,SetEndOfFile,[hFile] *,CloseHandle,[hFile]\n"
    "    rundllex WSAStartup,2,(16) {sock}socket,2,1,0^\n"
    "             {host}gethostbyname,doudemoexe.com^\n"
    "             {p}-o(*4=[*host.12]) {h_addr}-o[*p]^\n"
    "             connect,[sock],(16=0x50000002/[*h_addr]),16^\n"
    "             \"send,[sock],GET /Work/test.txt HTTP/1.0\\r\\n\\r\\n,31,0\"^\n"
    "             RECEIVE:{return}recv,[sock],{buff}(256),256,0^\n"
    "             fwrite,[buff],[return],1,[stdout] \"-o[return]>0,RECEIVE\"^\n"
    "             closesocket,[sock] fflush,[stdout] puts,# WSACleanup"
  );
  exit(0);
}

void OperationCmd(HEAP *heap, INVOKER *invoker)
{
  int result;
  int operand[2];
  char *operation, *jumpIndexStr;
  char buff[BUFFER_SIZE];

  strcpy(buff, invoker->dllName + 2);
  jumpIndexStr = invoker->apiName;

  operation = ParseOperationExp(buff, operand, heap);

  ExtendHeap(heap, 4);
  result = DoOperation(operand, operation);
  *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] = result;
  if (jumpIndexStr && *jumpIndexStr && result) ChangeRunIndex(heap, jumpIndexStr);
}

void ModificationCmd(HEAP *heap, INVOKER *invoker)
{
  int result;
  int operand[2];
  int *dst;
  char *operation, *jumpIndexStr;
  char buff[BUFFER_SIZE];

  strcpy(buff, invoker->dllName + 2);
  jumpIndexStr = invoker->apiName;

  operation = ParseOperationExp(buff, operand, heap);
  if (strcmp(operation, "=")) ERROREXIT(E_ILLEGAL_ARGS, NULL);
  dst = (int*)operand[0];
  operand[0] = *((int*)operand[0]);

  ExtendHeap(heap, 4);
  result = operand[1];
  *(int*)&heap->data[heap->cur][heap->size[heap->cur]-4] = result;
  *dst = result;
  if (jumpIndexStr && *jumpIndexStr && result) ChangeRunIndex(heap, jumpIndexStr);
}

char *ParseOperationExp(char *expression, int *operand, HEAP *heap)
{
  int i;
  char *operation, *pOpeEnd;
  ANALYSIS_METHOD am = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };

  if (*expression == '\0') ERROREXIT(E_ILLEGAL_ARGS, NULL);
  operand[0] = GetArgValue(&expression, heap, &am, "=+-*/%|&^><!~");
  operation = expression++;
  if (*operation) {
    if (*expression == '>' || *expression == '<' || *expression == '=') ++expression;
    pOpeEnd = expression;
    operand[1] = GetArgValue(&expression, heap, &am, "");
    *pOpeEnd = '\0';
  }

  return operation;
}

int DoOperation(int *operand, char *operation)
{
  if (!*operation) return *operand;

  if (operation[1]) {
    if      (!strcmp(operation, "==")) return operand[0] == operand[1];
    else if (!strcmp(operation, "<=")) return operand[0] <= operand[1];
    else if (!strcmp(operation, ">=")) return operand[0] >= operand[1];
    else if (!strcmp(operation, "!=")) return operand[0] != operand[1];
    else if (!strcmp(operation, "<<")) return operand[0] << operand[1];
    else if (!strcmp(operation, ">>")) return operand[0] >> operand[1];
    else                               ERROREXIT(E_ILLEGAL_ARGS, NULL);
  } else {
    switch (operation[0]) {
    case '+': return operand[0] + operand[1];
    case '-': return operand[0] - operand[1];
    case '*': return operand[0] * operand[1];
    case '/': return operand[0] / operand[1];
    case '%': return operand[0] % operand[1];
    case '|': return operand[0] | operand[1];
    case '&': return operand[0] & operand[1];
    case '^': return operand[0] ^ operand[1];
    case '>': return operand[0] > operand[1];
    case '<': return operand[0] < operand[1];
    case '!': return !operand[1];
    case '~': return ~operand[1];
    default:  ERROREXIT(E_ILLEGAL_ARGS, NULL);
    }
  }
  return 0;
}

void ChangeRunIndex(HEAP *heap, char *label)
{
  int i, length;
  int index = GetIndex(&label, heap->cur, "");
  char buff[BUFFER_SIZE];

  if (index == -1) {
    sprintf(buff, "%s:", label);
    length = strlen(buff);
    for (i = 0; i < g_contextList[heap->contextIndex]->stmtCount; ++i) {
      if (!strncmp(g_contextList[heap->contextIndex]->stmtList[i], buff, length)) {
        index = i;
        break;
      }
    }
    if (i == g_contextList[heap->contextIndex]->stmtCount) ERROREXIT(E_LABEL_NOT_FOUND, label);
  }

  heap->cur = index - 1;
}

void ChangeRunIndexToBlockStart(HEAP *heap, char *blockStartStr)
{
  int i, length, nest = 1;
  char buff[BUFFER_SIZE], blockEndStr[BUFFER_SIZE];
  char *pBuff;

  strrvs(blockEndStr, blockStartStr);
  length = strlen(blockStartStr);
  for (i = heap->cur - 1; i >= 0; --i) {
    pBuff = strchr(strcpy(buff, g_contextList[heap->contextIndex]->stmtList[i]), ',');
    if (pBuff) *pBuff = '\0';
    pBuff = strchr(buff, '\0') - length;
    if (!strcmp(pBuff, blockEndStr))   ++nest;
    if (!strcmp(pBuff, blockStartStr)) --nest;
    if (!nest) break;
  }
  if (i < 0) ERROREXIT(E_BLOCK_START_NOT_FOUND, blockStartStr);

  heap->cur = i - 1;
}

void ChangeRunIndexToBlockEnd(HEAP *heap, char *blockEndStr)
{
  int i, length, nest = 1;
  char buff[BUFFER_SIZE], blockStartStr[BUFFER_SIZE];
  char *pBuff;

  strrvs(blockStartStr, blockEndStr);
  length = strlen(blockEndStr);
  for (i = heap->cur + 1; i < g_contextList[heap->contextIndex]->stmtCount; ++i) {
    pBuff = strchr(strcpy(buff, g_contextList[heap->contextIndex]->stmtList[i]), ',');
    if (pBuff) *pBuff = '\0';
    pBuff = strchr(buff, '\0') - length;
    if (!strcmp(pBuff, blockStartStr)) ++nest;
    if (!strcmp(pBuff, blockEndStr))   --nest;
    if (!nest) break;
  }
  if (i == g_contextList[heap->contextIndex]->stmtCount) ERROREXIT(E_BLOCK_END_NOT_FOUND, blockEndStr);

  heap->cur = i;
}

int SearchElseBlock(HEAP *heap)
{
  int i, nest = 1;
  char buff[BUFFER_SIZE];
  char *pBuff;

  for (i = heap->cur + 1; i < g_contextList[heap->contextIndex]->stmtCount; ++i) {
    pBuff = strchr(strcpy(buff, g_contextList[heap->contextIndex]->stmtList[i]), ',');
    if (pBuff) *pBuff = '\0';
    pBuff = strchr(buff, '\0') - 2;
    if (!strcmp(pBuff, "-i")) ++nest;
    if (!strcmp(pBuff, "-i")) --nest;
    if (!nest) return 0;
    if (nest == 1 && !strcmp(pBuff, "-e")) break;
  }
  if (i == g_contextList[heap->contextIndex]->stmtCount) return 0;

  heap->cur = i - 1;
  return 1;
}

void GetTargetName(char *arg, INVOKER *invoker)
{
  int length = strlen(arg);
  char *splitPos;

  if (length == 0) ERROREXIT(E_ILLEGAL_ARGS, NULL);
  if (length > BUFFER_SIZE - 2) ERROREXIT(E_ARG_TOO_LONG, (void*)GetHeap()->cur);
  strcpy(invoker->stmtBuff, arg);
  invoker->dllName = strtokex(&invoker->stmtBuff, ",");
  splitPos = strchr(invoker->dllName, ':');
  if (invoker->dllName == splitPos) ERROREXIT(E_INVALID_LABEL, NULL);
  if (splitPos) invoker->dllName = splitPos + 1;
  if (*invoker->dllName == '{') invoker->refName = GetVarName(&invoker->dllName);
  else                          invoker->refName = NULL;
  if (!IsEllipsisDllName(invoker)) invoker->apiName = strtokex(&invoker->stmtBuff, ",");
}

int IsEllipsisDllName(INVOKER *invoker)
{
  return strcmp(invoker->dllName, "*") && !LoadLibrary(invoker->dllName) &&
         !strchr(invoker->dllName, '.') && *invoker->dllName != '-' && *invoker->dllName != '/';
}

void DecisionFirstArgType(INVOKER *invoker)
{
  if (IsEllipsisDllName(invoker)) {
    invoker->apiName = invoker->dllName;
    invoker->dllName = IsNameChar(*invoker->apiName) ? (char*)g_allDll : NULL ;
  }
}

BOOL SetAPIAddress(HEAP *heap, INVOKER *invoker)
{
  HMODULE  dll;
  Win32API api;
  int i, j, count, ordinal;
  char *dllName = invoker->dllName, *apiName;
  char apiNameBuff[BUFFER_SIZE];
  char *estr = "";
  BOOL rollBackTokenBuffer = FALSE;
  ANALYSIS_METHOD am = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };

  if (heap->runTrace[heap->cur] == TRUE) return FALSE;
  if (invoker->apiName == NULL) ERROREXIT(E_ILLEGAL_ARGS, NULL);
  if (dllName == NULL) {
    invoker->api[heap->cur] = (Win32API)GetArgValue(&invoker->apiName, heap, &am, "");
    return FALSE;
  }

  ordinal = strtol(invoker->apiName, &estr, 10);
  if (*estr == '\0') {
    apiName = (char*)ordinal;
    if (!strcmp(dllName, "*")) ERROREXIT(E_ILLEGAL_ARGS, NULL);
  } else {
    apiName = strcpy(apiNameBuff, invoker->apiName);
  }

  while (1) {
    for (i = 0, api = NULL; i < 2 && api == NULL; ++i) {
      if (!strcmp(dllName, "*")) {
        for (j = 0, count = sizeof(g_dllList) / sizeof(char*); j < count; ++j) {
          dll = LoadLibrary(g_dllList[j]);
          if (dll == NULL) continue;
          api = (Win32API)GetProcAddress(dll, apiName);
          if (api == NULL) FreeLibrary(dll);
          else             break;
        }
      } else {
        dll = LoadLibrary(dllName);
        if (dll == NULL) ERROREXIT(E_DLL_NOT_FOUND, dllName);
        api = (Win32API)GetProcAddress(LoadLibrary(dllName), apiName);
      }
      if (*estr == '\0') break;
      else               strcat(apiName, "A");
    }
    if (api == NULL) {
      if (*dllName != '*' && !strchr(dllName, '.') && *estr != '\0') {
        apiName = strcpy(apiNameBuff, dllName);
        dllName = (char*)g_allDll;
        rollBackTokenBuffer = TRUE;
        continue;
      }
      if (*estr == '\0') sprintf(apiName = apiNameBuff, "ordinal=%d", ordinal);
      else               apiName = invoker->apiName;
      ERROREXIT(E_API_NOT_FOUND, apiName);
    }
    break;
  }

  invoker->api[heap->cur] = api;
  return rollBackTokenBuffer;
}

void CreateAPIArgs(HEAP *heap, INVOKER *invoker)
{
  char *arg;
  int args[MAX_ARG_COUNT];
  int argCount = 0;
  ANALYSIS_METHOD am = { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE };

  while ((arg = strtokex(&invoker->stmtBuff, ",")) != NULL) {
    if (argCount == MAX_ARG_COUNT) ERROREXIT(E_ARG_LIST_TOO_LONG, NULL);
    args[argCount++] = GetArgValue(&arg, heap, &am, "");
  }

  CreatePushInstruction((char*)invoker->pushArgs, args, argCount);
  ExtendHeap(heap, 4);
  DetermineHeap(heap);
}

int GetArgValue(char **arg, HEAP *heap, ANALYSIS_METHOD *am, char *delims)
{
  int argValue;
  char *varName;
  char *estr = "";
  BOOL ref = TRUE;

  if (!*arg || !**arg) return 0;
  if (am->allowVar == TRUE) varName = **arg == '{' ? GetVarName(arg) : NULL;
  switch (**arg) {
  case '(':
    if (am->allowAlloc == FALSE) ERROREXIT(E_ILLEGAL_ARGS, NULL);
    ++*arg;
    argValue = GetAllocArgValue(arg, heap);
    break;
  case '[':
    if (am->allowRef == FALSE) ERROREXIT(E_ILLEGAL_ARGS, NULL);
    ++*arg;
    argValue = GetRefArgValue(arg, heap);
    break;
  case '\'':
    if (am->allowExp == FALSE) ERROREXIT(E_ILLEGAL_ARGS, NULL);
    ++*arg;
    argValue = GetExpArgValue(arg);
    ref = FALSE;
    break;
  default:
    if (am->allowImm == FALSE) ERROREXIT(E_ILLEGAL_ARGS, NULL);
    if (am->allowStr == TRUE) {
      argValue = GetImmArgValue(arg, heap, &estr, delims);
      ref = *estr != '\0' ? TRUE : FALSE;
    } else {
      argValue = strtolex(arg, &estr, TRUE);
      if (!strchr(delims, *estr)) ERROREXIT(E_ILLEGAL_ARGS, NULL);
      ref = FALSE;
      *arg += *estr ? estr - *arg : strlen(*arg);
    }
    break;
  }
  if (am->allowVar == TRUE && varName) SetVar(varName, argValue, ref, FALSE);
  while (!strchr(delims, **arg)) ++*arg;

  return argValue;
}

int GetAllocArgValue(char **arg, HEAP *heap)
{
  int allocSize, argValue, initIndex, initValue;
  BOOL dereference = FALSE;
  char *pBuff;
  char buff[BUFFER_SIZE];
  ANALYSIS_METHOD am = { FALSE, FALSE, TRUE, TRUE, FALSE, TRUE };

  pBuff = strcpy(buff, *arg);
  if (*pBuff == '*') {
    ++pBuff;
    dereference = TRUE;
  }
  allocSize = GetArgValue(&pBuff, heap, &am, "=)");
  if (allocSize < 0) ERROREXIT(E_ILLEGAL_ARGS, NULL);
  ExtendHeap(heap, allocSize);
  argValue = (int)(heap->data[heap->cur] + heap->size[heap->cur] - allocSize);
  am.allowStr = TRUE;
  for (initIndex = 0; *pBuff != ')';) {
    ++pBuff;
    initValue = GetArgValue(&pBuff, heap, &am, "/)");
    if (heap->runTrace[heap->cur] == FALSE) *(((int*)argValue) + initIndex++) = initValue;
  }
  if (dereference == TRUE) argValue = *(int*)argValue;
  *arg += pBuff - buff;

  return argValue;
}

int GetRefArgValue(char **arg, HEAP *heap)
{
  int argValue, offset, length;
  BOOL dereference = FALSE;
  char *pBuff, *pbrk;
  char buff[BUFFER_SIZE], varName[BUFFER_SIZE];
  ANALYSIS_METHOD am = { FALSE, FALSE, TRUE, TRUE, FALSE, TRUE };

  pBuff = strcpy(buff, *arg);
  if (*pBuff == '*') {
    ++pBuff;
    dereference = TRUE;
  }
  argValue = GetIndex(&pBuff, heap->cur, ".]");
  pbrk = strpbrk(pBuff, ".]");
  length = pbrk ? pbrk - pBuff : strlen(pBuff);
  ((char*)memcpy(varName, pBuff, length))[length] = '\0';
  pBuff += length;
  if (argValue == -1) {
    offset = 0;
    argValue = GetVar(varName);
  } else {
    offset = heap->size[argValue] - 4;
    argValue = (int)heap->data[argValue];
  }
  offset   = *pBuff == ']'          ? 0
           : !strcmp(++pBuff, "r]") ? ++pBuff, offset
                                    : GetArgValue(&pBuff, heap, &am, "]");
  argValue = (int)((char*)argValue + offset);
  if (dereference == TRUE) argValue = *(int*)argValue;
  *arg += pBuff - buff;

  return argValue;
}

int GetExpArgValue(char **arg)
{
  int argValue, length;
  char buff[BUFFER_SIZE];

  length = strchr(*arg, '\'') - *arg;
  ((char*)memcpy(buff, *arg, length))[length] = '\0';
  argValue = EvalExp(buff);
  *arg += length;

  return argValue;
}

int GetImmArgValue(char **arg, HEAP *heap, char **estr, char *delims)
{
  int argValue, length;
  char buff[BUFFER_SIZE], tmpArg[BUFFER_SIZE], *pbrk, *pTmpArg;

  pbrk = strpbrk(*arg, delims);
  length = pbrk ? pbrk - *arg : strlen(*arg);
  ((char*)memcpy(tmpArg, *arg, length))[length] = '\0';
  *arg += length;
  pTmpArg = tmpArg;

  argValue = strtolex(&pTmpArg, estr, FALSE);
  if (estr != NULL && **estr != '\0') {
    if (*pTmpArg == '#') {
      length = strlen(++pTmpArg);
    } else if (*pTmpArg == '$') {
      length = mbstowcs(NULL, ++pTmpArg, 0);
      if (length * 2 > BUFFER_SIZE - 2) ERROREXIT(E_ARG_TOO_LONG, (void*)heap->cur);
      mbstowcs((wchar_t*)buff, pTmpArg, length + 1);
      length = length * 2 + 1;
      pTmpArg = buff;
    } else {
      length = ConvertStr(pTmpArg, buff);
      pTmpArg = buff;
    }
    argValue = (int)RegisterStr(heap, pTmpArg, length);
  }

  return argValue;
}

int ConvertStr(char *arg, char *buff)
{
  int index = 0;
  int escape;

  while (*arg) {
    if (*arg == '\\') {
      switch (*++arg) {
      case 'a':  escape = 7;    break;
      case 'b':  escape = 8;    break;
      case 'c':  escape = 44;   break;
      case 'n':  escape = 10;   break;
      case 'r':  escape = 13;   break;
      case 'f':  escape = 12;   break;
      case 't':  escape = 9;    break;
      case 'v':  escape = 11;   break;
      case '0':  escape = '\0'; break;
      case '\\': escape = '\\'; break;
      case '\?': escape = '\?'; break;
      case '\'': escape = '\''; break;
      case '\"': escape = '\"'; break;
      case 'x':
        if (!IsHexChar(arg[1]) || !IsHexChar(arg[2])) continue;
        escape = (char)(HexCharToInt(arg[1]) * 16 + HexCharToInt(arg[2]));
        arg += 2;
        break;
      default:
        if (IsNumChar(arg[0])) {
          if (IsFirstOctChar(arg[0]) && IsOctChar(arg[1]) && IsOctChar(arg[2])) {
            escape = (char)(OctCharToInt(arg[0]) * 64 + OctCharToInt(arg[1]) * 8 + OctCharToInt(arg[2]));
            arg += 2;
            break;
          } else {
            if (*arg == '0') {
              escape = '\0';
              break;
            }
          }
        }
        continue;
      }
      buff[index++] = escape;
      ++arg;
    } else {
      buff[index++] = *arg++;
    }
  }
  buff[index] = '\0';

  return index;
}

int GetIndex(char **arg, int cur, char *delims)
{
  int index = 0;
  char *estr = "";

  if (**arg == '+' || **arg == '-') index = (*(*arg)++ - 44) * -1;
  index = (!!index) * cur + ((index+2)/2*2-1) * strtolex(arg, &estr, FALSE);
  if (*estr != '\0') {
    *arg = estr;
    if (!strchr(delims, *estr)) return -1;
  }
  if (index < 0) ERROREXIT(E_ILLEGAL_ARGS, NULL);

  return index;
}

void CreatePushInstruction(char *pushArgs, int *args, int argCount)
{
  int offset = 0;

  pushArgs[offset++] = 0x5a;
  pushArgs[offset++] = 0x89;
  pushArgs[offset++] = 0xe0;
  while (--argCount >= 0) {
    pushArgs[offset++] = 0x68;
    *((int*)&pushArgs[offset]) = args[argCount];
    offset += sizeof(int);
  }
  pushArgs[offset++] = 0xff;
  pushArgs[offset]   = 0xe2;
}

void CallAPI(HEAP *heap, INVOKER *invoker)
{
  int returnValue, esp, ebx, cur;
  DWORD lastError, length;
  char *orgRefName;

  SetLastError(0);
  cur = heap->cur;
  esp = invoker->pushArgs();
  ebx = g_getEBX();
  returnValue = invoker->api[heap->cur]();
  g_setEBX(ebx);
  g_popInstruction(esp);
  heap->cur = cur;

  heap->isReturn = 0;
  *((int*)&heap->data[heap->cur][heap->size[heap->cur] - 4]) = returnValue;
  lastError = GetLastError();
  length = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, lastError, 0, g_lastErrorStr, 1023, NULL) - 1;
  while (g_lastErrorStr[length] == '\n' || g_lastErrorStr[length] == '\r') g_lastErrorStr[length--] = '\0';
  SetVar("__LE", lastError, FALSE, TRUE);
  SetVar("__LES", (int)g_lastErrorStr, TRUE, TRUE);
}

/****************************************************************************************
                       (@@) (  ) (@)  ( )  @@    ()    @     O     @     O      @
                  (   )
              (@@@@)
           (    )

         (@@@)
      ====        ________                ___________
  _D _|  |_______/        \__I_I_____===__|_________|
   |(_)---  |   H\________/ |   |        =|___ ___|      _________________
   /     |  |   H  |  |     |   |         ||_| |_||     _|                \_____A
  |      |  |   H  |__--------------------| [___] |   =|                        |
  | ________|___H__/__|_____/[][]~\_______|       |   -|                        |
  |/ |   |-----------I_____I [][] []  D   |=======|____|________________________|_
__/ =| o |=-~~\  /~~\  /~~\  /~~\ ____Y___________|__|__________________________|_
 |/-=|___|=O=====O=====O=====O   |_____/~\___/          |_D__D__D_|  |_D__D__D_|
  \_/      \__/  \__/  \__/  \__/      \_/               \_/   \_/    \_/   \_/
****************************************************************************************/

#define ANIMATION_SLEEP_TIME        30
#define SL_LEFTDOWN_FRAME_DURATION  1
#define SMOKE_FRAME_DURATION        4
#define SL_WIDTH                    83
#define SL_HEIGHT                   16
#define SL_LEFT_WIDTH               53
#define SL_LEFTUP_HEIGHT            7
#define SL_LEFTDOWN_HEIGHT          3
#define SL_RIGHT_WIDTH              30
#define SL_RIGHT_HEIGHT             10
#define SMOKE_WIDTH                 80
#define SMOKE_HEIGHT                6

typedef struct {
  short x;
  short y;
  short w;
  short h;
  char *data;
} CIMAGE;

static const HANDLE g_hStdout;  /* 標準出力ハンドル */
static const CIMAGE g_screen;   /* スクリーンバッファ */

static const char *g_SmokeAnimeData[] = {
  "                      (  ) (@@) ( )  (@)  ()    @@    O     @     O     @      O"
  "                 (@@@)                                                          "
  "             (    )                                                             "
  "          (@@@@)                                                                "
  "                                                                                "
  "        (   )                                                                   ",

  "                      (@@) (  ) (@)  ( )  @@    ()    @     O     @     O      @"
  "                 (   )                                                          "
  "             (@@@@)                                                             "
  "          (    )                                                                "
  "                                                                                "
  "        (@@@)                                                                   ",
};
static const char g_SLLeftUpData[] = {
  "      ====        ________                ___________"
  "  _D _|  |_______/        \\__I_I_____===__|_________|"
  "   |(_)---  |   H\\________/ |   |        =|___ ___|  "
  "   /     |  |   H  |  |     |   |         ||_| |_||  "
  "  |      |  |   H  |__--------------------| [___] |  "
  "  | ________|___H__/__|_____/[][]~\\_______|       |  "
  "  |/ |   |-----------I_____I [][] []  D   |=======|__"
};
static const char *g_SLLeftDownData[] = {
  "__/ =| o |=-~~\\  /~~\\  /~~\\  /~~\\ ____Y___________|__"
  " |/-=|___|=    ||    ||    ||    |_____/~\\___/       "
  "  \\_/      \\_O=====O=====O=====O/      \\_/           ",

  "__/ =| o |=-~~\\  /~~\\  /~~\\  /~~\\ ____Y___________|__"
  " |/-=|___|=   O=====O=====O=====O|_____/~\\___/       "
  "  \\_/      \\__/  \\__/  \\__/  \\__/      \\_/           ",

  "__/ =| o |=-~O=====O=====O=====O\\ ____Y___________|__"
  " |/-=|___|=    ||    ||    ||    |_____/~\\___/       "
  "  \\_/      \\__/  \\__/  \\__/  \\__/      \\_/           ",

  "__/ =| o |=-O=====O=====O=====O \\ ____Y___________|__"
  " |/-=|___|=    ||    ||    ||    |_____/~\\___/       "
  "  \\_/      \\__/  \\__/  \\__/  \\__/      \\_/           ",

  "__/ =| o |=-~~\\  /~~\\  /~~\\  /~~\\ ____Y___________|__"
  " |/-=|___|=O=====O=====O=====O   |_____/~\\___/       "
  "  \\_/      \\__/  \\__/  \\__/  \\__/      \\_/           ",

  "__/ =| o |=-~~\\  /~~\\  /~~\\  /~~\\ ____Y___________|__"
  " |/-=|___|=    ||    ||    ||    |_____/~\\___/       "
  "  \\_/      \\O=====O=====O=====O_/      \\_/           ",
};
static const char g_SLRightData[] = {
  "                              "
  "                              "
  "    _________________         "
  "   _|                \\_____A  "
  " =|                        |  "
  " -|                        |  "
  "__|________________________|_ "
  "|__________________________|_ "
  "   |_D__D__D_|  |_D__D__D_|   "
  "    \\_/   \\_/    \\_/   \\_/    "
};

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);
void InitScreenInfo(void);
void FlushScreenBuffer(void);
void RenderImage(const CIMAGE *src, const CIMAGE *dst);
void ClearImage(const CIMAGE *image);
void ClearImageRect(const CIMAGE *image, int x, int y, int w, int h);
void SLAnimation(void);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
  // Ctrl + C, Ctrl + break, Closeイベントが飛んできたら無限sleep
  switch (dwCtrlType) {
  case CTRL_CLOSE_EVENT:
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
    Sleep(INFINITE);
    break;
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    return FALSE;
  }

  return TRUE;
}

void InitScreenInfo(void)
{
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  CIMAGE *screen = (CIMAGE*)&g_screen;

  /* コンソール画面の情報を取得 */
  *(HANDLE*)&g_hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
  GetConsoleScreenBufferInfo(g_hStdout, &csbi);

  /* スクリーンサイズの設定 */
  screen->x = 0;
  screen->y = csbi.srWindow.Top;
  screen->w = csbi.dwSize.X;
  screen->h = csbi.srWindow.Bottom - csbi.srWindow.Top;

  /* バッファ領域確保 */
  screen->data = (char*)malloc(screen->h * screen->w);
  ClearImage(screen);
}

void FlushScreenBuffer(void)
{
  /* キャレット位置を左上原点にセット */
  SetConsoleCursorPosition(g_hStdout, *(COORD*)&g_screen.x);

  /* スクリーンバッファの内容を標準出力に転送 */
  fwrite(g_screen.data, 1, g_screen.w * g_screen.h, stdout);
}

void RenderImage(const CIMAGE *src, const CIMAGE *dst)
{
  /* dstに転送するsrcの領域を計算 */
  int xoffset = GetMin(src->x, 0) * -1;
  int yoffset = GetMin(src->y, 0) * -1;
  int xlength = GetMax(src->w - xoffset - max(src->x + src->w - dst->w, 0), 0);
  int ylength = GetMax(src->h - yoffset - max(src->y + src->h - dst->h, 0), 0);
  /* dstの転送原点 */
  int baseIndex = max(src->y * dst->w, 0) + src->x + xoffset;
  int y;

  /* 転送領域が無い場合はreturn */
  if (!xlength || !ylength) return;

  /* srcの内容をdstに転送 */
  for (y = 0; y < ylength; ++y) {
    memcpy(
      dst->data + baseIndex + y * dst->w,
      src->data + xoffset + (y + yoffset) * src->w,
      xlength
    );
  }
}

void ClearImage(const CIMAGE *image)
{
  /* イメージのクリア */
  memset(image->data, ' ', image->w * image->h);
}

void ClearImageRect(const CIMAGE *image, int x, int y, int w, int h)
{
  int i;

  /* イメージの矩形領域クリア */
  for (i = 0; i < h; ++i) {
    memset(image->data + x + (y + i) * image->w, ' ', w);
  }
}

void SLAnimation(void)
{
  /* SLのベースイメージ */
  /*
   ┌────────┐
   │       1        │
   ├──────┬─┤
   │            │  │
   │      2     │  │
   ├──────┤4 │
   │      3     │  │
   └──────┴─┘
  */
  CIMAGE slImage = { 0, 4, SL_WIDTH, SL_HEIGHT, NULL };
  /* 煙のイメージ */
  CIMAGE smokeImage = { 0, 0, SMOKE_WIDTH, SMOKE_HEIGHT, NULL }; /* 1 */
  int curSmokeAnimeFrame = 0;
  /* SL本体のイメージ */
  CIMAGE slLeftUpImage = { /* 2 */
    0, SMOKE_HEIGHT, SL_LEFT_WIDTH, SL_LEFTUP_HEIGHT, (char*)g_SLLeftUpData
  };
  CIMAGE slLeftDownImage = { /* 3 */
    0, SMOKE_HEIGHT + SL_LEFTUP_HEIGHT, SL_LEFT_WIDTH, SL_LEFTDOWN_HEIGHT, NULL
  };
  CIMAGE slRightImage = { /* 4 */
    SL_LEFT_WIDTH, SMOKE_HEIGHT, SL_RIGHT_WIDTH, SL_RIGHT_HEIGHT, (char*)g_SLRightData
  };
  int curSLAnimeFrame = 0;

  /* アニメーション開始前初期状態のセット */
  slImage.x = g_screen.w;
  slImage.data = (char*)malloc(slImage.w * slImage.h);
  ClearImage(&slImage);
  RenderImage(&slLeftUpImage, &slImage);
  RenderImage(&slRightImage, &slImage);

  /* SLのアニメーション */
  while (1) {
    ClearImage(&g_screen);

    /* 煙のアニメーションイメージ作成 */
    ClearImageRect(&slImage, 0, 0, SL_WIDTH, SMOKE_HEIGHT);
    if (curSmokeAnimeFrame / SMOKE_FRAME_DURATION == sizeof(g_SmokeAnimeData) / sizeof(char*)) {
      curSmokeAnimeFrame = 0;
    }
    smokeImage.x = curSmokeAnimeFrame % SMOKE_FRAME_DURATION;
    smokeImage.data = (char*)g_SmokeAnimeData[curSmokeAnimeFrame++ / SMOKE_FRAME_DURATION];
    RenderImage(&smokeImage, &slImage);

    /* SLのアニメーションイメージ作成 */
    if (curSLAnimeFrame / SL_LEFTDOWN_FRAME_DURATION == sizeof(g_SLLeftDownData) / sizeof(char*)) {
      curSLAnimeFrame = 0;
    }
    slLeftDownImage.data = (char*)g_SLLeftDownData[curSLAnimeFrame++ / SL_LEFTDOWN_FRAME_DURATION];
    RenderImage(&slLeftDownImage, &slImage);

    /* イメージを画面に転送 */
    RenderImage(&slImage, &g_screen);
    FlushScreenBuffer();
    Sleep(ANIMATION_SLEEP_TIME);

    /* イメージの移動とアニメーション終了判定 */
    if (--slImage.x < -slImage.w) break;
  }
}

void slmain(void)
{
  SetConsoleCtrlHandler(HandlerRoutine, TRUE);
  InitScreenInfo();
  SLAnimation();
  exit(0);
}

TOKEN **GetTokenList(char *srcText, int *retCount)
{
  TOKEN **tokenList = NULL;
  void *ext, *func;
  int tokenType, c;
  int tokenCount = 0, tokenCapa = 0;
  char *start;

  for (start = srcText; c = *srcText; start = srcText, ext = NULL) {
    switch (tokenType = GetTokenType(c)) {
    case TT_IDENTIFIER:
      while (IsIdentifierChar(*srcText)) ++srcText;
      break;
    case TT_NUMBER:
      ext = malloc(sizeof(NUMBER_INFO));
      ((NUMBER_INFO*)ext)->base = 10;
      if (c == '0') {
        switch (c = srcText[1]) {
        case 'x':
        case 'X':
          srcText += 2;
          ((NUMBER_INFO*)ext)->base = 16;
          break;
        default:
          if (IsNumberChar(c)) ((NUMBER_INFO*)ext)->base = 8;
        }
      }
      while (IsNumberChar(*srcText)) ++srcText;
      break;
    case TT_OPERATOR:
      ext = malloc(sizeof(OPERATOR_INFO));
      ((OPERATOR_INFO*)ext)->operandCount = 2;
      func = NULL;
      ++srcText;
      switch (c) {
      case '<':
        c = 7; func = OpeLess;
        switch (*srcText) {
        case '<': c = 8; func = OpeLeftShift; ++srcText; break;
        case '=': c = 7; func = OpeLessEqual; ++srcText; break;
        }
        break;
      case '>':
        c = 7; func = OpeGreater;
        switch (*srcText) {
        case '>': c = 8; func = OpeRightShift; ++srcText; break;
        case '=': c = 7; func = OpeGreaterEqual; ++srcText; break;
        }
        break;
      case '=':
        c = 6; func = OpeEqual;
        ++srcText;
        break;
      case '!':
        c = 11; func = OpeUnaryNot;
        if (*srcText == '=') c = 6, func = OpeNotEqual, ++srcText;
        else ((OPERATOR_INFO*)ext)->operandCount = 1;
        break;
      case '&':
        c = 5; func = OpeBitAnd;
        if (*srcText == '&') c = 2, func = OpeAnd, ++srcText;
        break;
      case '|':
        c = 3; func = OpeBitOr;
        if (*srcText == '|') c = 1, func = OpeOr, ++srcText;
        break;
      case '^': c = 4; func = OpeBitXor; break;
      case '+': c = 9; func = OpePlus; break;
      case '-': c = 9; func = OpeMinus; break;
      case '*': c = 10; func = OpeMulti; break;
      case '/': c = 10; func = OpeDiv; break;
      case '%': c = 10; func = OpeMod; break;
      case '~': c = 11; func = OpeUnaryBitNot; ((OPERATOR_INFO*)ext)->operandCount = 1; break;
      case '(': case ')': c = 12; break;
      }
      ((OPERATOR_INFO*)ext)->priority  = c;
      ((OPERATOR_INFO*)ext)->operation = func;
      break;
    case TT_UNKNOWN:
      ERROREXIT(E_INCORRECT_EXPRESSION, NULL);
    }
    if (tokenCount == tokenCapa) {
      tokenCapa ? tokenCapa *= 2 : (tokenCapa = 1);
      tokenList = realloc(tokenList, tokenCapa * sizeof(TOKEN));
    }
    tokenList[tokenCount++] = GetToken(start, srcText, tokenType, ext);
  }

  *retCount = tokenCount;
  return tokenList;
}

TOKEN *GetToken(char *textStart, char *textEnd, int tokenType, void *ext)
{
  TOKEN *token = (TOKEN*)malloc(sizeof(TOKEN));
  int length = textEnd - textStart;
  token->text = strncpy((char*)malloc(length + 1), textStart, length);
  token->text[length] = '\0';
  token->type = tokenType;
  token->ext = ext;
  return token;
}

int EvalExp(char *src)
{
  int tokenCount, index = 0;
  TOKEN **tokenList = GetTokenList(src, &tokenCount);

  return OperationTokenList(tokenList, tokenCount, &index);
}

int OperationTokenList(TOKEN **tokenList, int tokenCount, int *cur)
{
  TOKEN *curToken;
  TOKEN *operatorTokenStack[24];
  TOKEN **unaryOpeTokenList = NULL;
  int valueStack[24];
  int operatorIndex = 0, valueIndex = 0, unaryOpeCount = 0, unaryOpeCapa = 0, orgCur = *cur;

  while (*cur < tokenCount) {
    curToken = tokenList[(*cur)++];
    switch (curToken->type) {
    case TT_IDENTIFIER:
      valueStack[valueIndex++] = GetVar(curToken->text);
      break;
    case TT_NUMBER:
      valueStack[valueIndex++] = strtol(curToken->text, NULL, ((NUMBER_INFO*)curToken->ext)->base);
      break;
    case TT_OPERATOR:
      if (operatorIndex == valueIndex) {
        switch (*curToken->text) {
        case '*': ((OPERATOR_INFO*)curToken->ext)->operandCount = 1; ((OPERATOR_INFO*)curToken->ext)->operation = OpeDereference; break;
        case '+': ((OPERATOR_INFO*)curToken->ext)->operandCount = 1; ((OPERATOR_INFO*)curToken->ext)->operation = OpeUnaryPlus; break;
        case '-': ((OPERATOR_INFO*)curToken->ext)->operandCount = 1; ((OPERATOR_INFO*)curToken->ext)->operation = OpeUnaryMinus; break;
        }
        switch (*curToken->text) {
        case '(':
          valueStack[valueIndex++] = OperationTokenList(tokenList, tokenCount, cur);
          break;
        default:
          if (unaryOpeCount == unaryOpeCapa) {
            unaryOpeCapa ? unaryOpeCapa *= 2 : (unaryOpeCapa = 1);
            unaryOpeTokenList = realloc(unaryOpeTokenList, unaryOpeCapa * sizeof(TOKEN));
          }
          unaryOpeTokenList[unaryOpeCount++] = curToken;
        }
      } else {
        if (*curToken->text == ')') {
          if (orgCur == 0) ERROREXIT(E_INCORRECT_EXPRESSION, NULL);
          goto END_THIS_CALL;
        }
        while (operatorIndex && valueIndex >= 2 && ((OPERATOR_INFO*)curToken->ext)->priority <= ((OPERATOR_INFO*)operatorTokenStack[operatorIndex - 1]->ext)->priority) {
          valueStack[valueIndex - 2] = ((Operation2)((OPERATOR_INFO*)operatorTokenStack[operatorIndex - 1]->ext)->operation)(valueStack[valueIndex - 2], valueStack[valueIndex - 1]);
          --valueIndex;
          --operatorIndex;
        }
        operatorTokenStack[operatorIndex++] = curToken;
      }
      break;
    }
    if (operatorIndex < valueIndex) {
      while (unaryOpeCount) valueStack[valueIndex - 1] = ((Operation1)((OPERATOR_INFO*)unaryOpeTokenList[--unaryOpeCount]->ext)->operation)(valueStack[valueIndex - 1]);
    }
  }
  END_THIS_CALL:
  while (unaryOpeCount && valueIndex) valueStack[valueIndex - 1] = ((Operation1)((OPERATOR_INFO*)unaryOpeTokenList[--unaryOpeCount]->ext)->operation)(valueStack[valueIndex - 1]);
  while (operatorIndex && valueIndex >= 2) {
    valueStack[valueIndex - 2] = ((Operation2)((OPERATOR_INFO*)operatorTokenStack[operatorIndex - 1]->ext)->operation)(valueStack[valueIndex - 2], valueStack[valueIndex - 1]);
    --valueIndex;
    --operatorIndex;
  }
  if (valueIndex != 1 || operatorIndex != 0) ERROREXIT(E_INCORRECT_EXPRESSION, NULL);

  return valueStack[0];
}
