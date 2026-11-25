# This document describes requirements for MCDC tool

## Preface

### Terminology used

**Condition**: A leaf-level Boolean expression.

**Decision**: A top-level Boolean expressions. In other words, Decision
  is never a part of another Boolean expression.

**MC/DC**: Modified Condition/Decision Coverage

**"The tool"**: This MCDC tool that is being qualified.

## Software requirements

### Use C compiler for pre-processing and parsing

`MCDC~SREQ~UseClang~1`

**Description:**

The tool shall use `clang`-compatible compiler to pre-process source
code and obtain ASTs for each source file.

**Rationale:**

To ensure that source code being analysed in the save way as it does
the C compiler.

### Parse AST and find Boolean Expressions

`MCDC~SREQ~FindBoolExpr~1`

**Description:**

The tool shall parse AST provided by `clang`-compatible compiler and
identify Boolean expressions. Namely:

- Any expression that includes Boolean operators `&&`, `||` and `!`
- Any expression that includes relational operators `==`, `!=`, `<`, `<=`, `>`, `>=`
- A selection-header (per ISO/IEC 9899:2024) in `if` statement
- An expression (per ISO/IEC 9899:2024) in `do` and `while` statements
- An expression_opt (per ISO/IEC 9899:2024) in `for` statement
- A logical-OR-expression (per ISO/IEC 9899:2024) in Conditional (ternary) operator

**Rationale:**

To identify what exactly should be analysed.

### Identify Condition (leaf) statements

`MCDC~SREQ~IdentifyCond~1`

**Description:**

For each Boolean expression, the tool shall identify its
Conditions. The following is considered as a condition:

- Value of Boolean variable
- Bool-cast of non-boolean variable
- Relational operator `==`, `!=`, `<`, `<=`, `>`, `>=`
- Result of a function call cast to a Boolean value

**Rationale:**

This is basic requirement for MC/DC

### Handle C short circuit logic

`MCDC~SREQ~ShortCircuit~1`

**Description:**

The tool shall take into account that C language mandates short
circuit in Boolean Expression.

**Rationale:**

To produce correct coverage results for C code.

### Handle constants in Boolean Expressions

`MCDC~SREQ~HandleConstants~1`

**Description:**

The tool shall correctly handle constants and constant expressions
inside Boolean expressions.

**Rationale:**

To cover cases like `A && (true || false)` or `A && (10 < 12)` which
can emerge due to C source code pre-processing.

### Simplify double NOT expressions

`MCDC~SREQ~HandleDoubleNot~1`

**Description:**

The tool shall simplify double NOT expressions: `!!A => A`.

**Rationale:**

Double NOT expressions are often used to convert Non-Zero/Zero
values into explicit One/Zero values.

### Output seen outcomes for each Condition

`MCDC~SREQ~Outcomes~1`

**Description:**

The tool shall output outcomes for each Condition in a Boolean
expression into report file.

**Rationale:**

The tool does not calculate MC/DC metrics by itself. Instead it
provides raw data for the LCOV tool, so it can calculate the metrics
and present a report.

### Handle complex C constructs

`MCDC~SREQ~HandleComplexConstructs~1`

**Description:**

The tool shall handle Boolean expressions with the following
properties:

- A Boolean expression accesses a global variable
- A Boolean expression compares pointer against NULL
- There are multiple nested Boolean expressions
- A Boolean expression that has comparison against `sizeof` value
- A Boolean expression that has comparison against value of C enumeration
- A Boolean expression inside `__builtin_expect` expression
- A Boolean expression inside a C macros
- A Boolean expression that degenerates into a constant value
- A Boolean expression, which evaluation may cause execution of
  a `goto` operator
- A Boolean expression inside C statement expressions
- A Boolean expression whose value is discarded due to use of C
  comma operator
- A Boolean expression whose value is assigned to a variable

**Rationale:**

To cover real-word cases that may involve Boolean expressions.
