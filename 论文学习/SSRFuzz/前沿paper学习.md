# 1. Argus: All your (PHP) Injection-sinks are belong to us

**Core Problem It Solves:** Security tools rely on manually created lists of sensitive functions (sinks). These lists are always incomplete, causing tools to miss entire classes of vulnerabilities.

**Core Idea / Innovation:** Instead of looking at application code, Argus performs a deep analysis of the **PHP interpreter itself** to find every single API function that can lead to a dangerous low-level operation (like executing a command or deserializing an object).



**differ from SSRFuzz stage1?**

> **Argus** performs a **"white-box," structural analysis** of the PHP language *interpreter itself*.
>
> **SSRFuzz (Stage 1)** performs a **"black-box," behavioral analysis** of individual PHP functions as described in the *manual*. 



**How Argus Builds the Call-Graph?**

> Argus's primary challenge is to create a complete and accurate map (a call-graph) of all function calls within the entire PHP interpreter and its extensions. It achieves this using a **hybrid static-dynamic analysis** because neither method alone is sufficient.

Part A: Static Analysis of Binaries

> Argus begins by performing a **static analysis on the compiled binaries** of the PHP interpreter and its shared libraries, not the source code.
>
> It uses a disassembler (`objdump`) to inspect the machine code and builds an initial call-graph by identifying all direct `call` instructions between functions.
>
> **Limitation:** This static approach fails to resolve **indirect calls** made via function pointers, which are used extensively inside PHP for features like stream wrappers (e.g., for `phar://` or `http://` protocols). This leaves critical gaps in the graph.

Part B: Dynamic Analysis for Refinement

> To fill the gaps left by static analysis, Argus uses dynamic tracing.
>
> It compiles the PHP interpreter with a special flag (`-pg`) that instruments every function entry and exit point.
>
> It then runs PHP's official, high-coverage unit test suite while using a tracing tool (`uftrace`) to record the actual sequences of function calls that occur during execution.
>
> Finally, Argus iterates over these dynamic execution traces and **adds any missing edges** (the indirect calls that were previously missed) to the statically generated call-graph. This hybrid method results in a far more complete call-graph than a purely static approach.



**How Argus Checks if a Sink Can Be Reached (Reachability Analysis)**

a. find sink (as dst)

b. find every PHP API (as src)

c. path traversal (src -> ... -> dst)

d. if find , auto generate the test script to valid



**复现**：

主要是sink寻找部分，

```bash
root@6f7ab6ce14c0:/home/step-1/argus# ls
analyze.pyc  enum  func_addr  graph_php5.6  libs  php_decompiled
```

各自的作用：

- analyze.pyc: 主分析脚本，“构建调用图”、“可达性分析”和“验证”
- enum/ : 这个目录里存放的是一个自定义的C语言PHP扩展的源代码。解决“**如何找到所有PHP对外暴露的API函数**”这个问题。这个扩展被加载到PHP解释器后，可以访问PHP的内部数据结构（如`function_table`），从而准确地获取所有API函数的名称及其在内存中的地址或内部符号名。
- func_addr: **函数地址列表**文件。这个文件是上面`enum`扩展运行后的**输出结果**。 它是一个数据文件，里面存储了从PHP解释器内部提取出的、所有可被用户调用的API函数列表及其对应的内部名称/地址。`analyze.pyc`会读取这个文件，来确定在调用图分析中，哪些节点是“源头”（Sources）。
- graph_php5.6: 这个目录里存放的是**预先录制好的动态函数调用轨迹**。这是Argus“混合分析”中**动态**部分的数据来源。研究人员已经提前运行了PHP 5.6的官方测试用例，并使用`uftrace`工具记录下了所有函数的实际调用顺序。`analyze.pyc`会读取这些轨迹，来发现静态分析无法找到的**间接调用**（比如通过函数指针的调用），从而补全调用图。
- php_decompiled 和 libs：这两个目录存放的是PHP解释器和其扩展库（libs）的二进制文件被反编译后的汇编代码。作用:** 这是Argus“混合分析”中**静态**部分的数据来源。`analyze.pyc`会读取和解析这些**反编译后的代码，通过识别`call`等指令**，来构建一个初始的、不完整的静态调用图。

工作流程：

1.启动。运行主脚本 `analyze.pyc`。

2.构建静态图: `analyze.pyc` 首先读取 `php_decompiled` 和 `libs` 目录中的反汇编代码，构建一个基础的、静态的调用图。

3.补全动态边：读取 `graph_php5.6` 目录中的动态执行轨迹，找到静态分析遗漏的间接调用，将这些“边”补充到调用图中，形成一个更完整的混合图。

4.确定分析起点(source)：读取 `func_addr` 文件，从而在完整的调用图上标记出所有作为“源头”的PHP API节点。

5.执行分析：在这个完整且标记好的图上，执行从API（src）到VIFs（dst）的可达性分析，找出所有潜在的sink函数。



找到的sink通过写入 `/home/psalm/stubs/CoreGenericFunctions.phpstub` 的方式来增加sink，并在插件上进行验证，发现增加一个sink，多发现了2个反序列化漏洞。



# 2. Atropos: Effective Fuzzing of Web Applications for Server-Side Vulnerabilities

**Core Problem It Solves:** Traditional fuzzers fail on web applications because they can't handle session state and don't understand the required input structure (e.g., specific keys like `username` in a POST request).



**Core Idea / Innovation:** Atropos introduces two key techniques from systems fuzzing to solve these problems:

1. **Snapshot-Based Execution:** It takes a "snapshot" of the entire application's state before running a test and reverts to it afterward. This isolates tests and is much faster than restarting the application every time.
2. **Interpreter-Level Feedback:** It instruments the PHP interpreter to watch which keys the application accesses from arrays like `$_GET` and `$_POST`. This feedback teaches the fuzzer the valid keys it needs to use to get past initial checks and explore deeper code paths.

**Inferring Values from String Comparisons**

- hook zend_string_equal_val e.g, $_POST['action'] == 'delete' , and extract `delete`

**Inferring Values from Regular Expressions**

- hook preg_match and use XEGER to generate the string



**8 bug oracles**



**how it fuzz?**

it uses AFL++ custom mutator, patch `pcov` to afl-like bitmap to feedback coverage



**how to confirm a bug?**

- sink detection(detect error / access)
- take sqli as example: **insert a special string** into the input and observe if this string appears in the query



比较SSRFuzz，SSRFuzz打标签是为了精确识别出input参数，缩小fuzz空间

SSRFuzz的确认用的是OAST回调

Atropos缩小fuzzing空间用的是inferring一些硬编码的值，来模拟更深入，更正确的输入



**Key Implementation Details**

- The Snapshotting Engine (NYX): a specialized system designed for high-speed, full-system snapshotting in a fuzzing context
- Bypassing the Web Server (FastCGI) : to maximize performance ; bypasses the overhead of HTTP parsing and web server processing