# Git-Like Version Control System in C++

## Project Description

This project implements a simplified Git-inspired version control system in C++ for managing large CSV datasets in collaborative environments. Instead of resending entire files after each change, it uses tree data structures (AVL Tree, B-Tree, or Red-Black Tree) to store and manage data efficiently. Each node is stored in a separate file, and hashing (using either a custom instructor method or SHA-256) is employed to ensure data integrity.

By leveraging Merkle Trees, the system detects data corruption and transfers only changed parts of the dataset, significantly optimizing bandwidth and memory usage. It also supports key Git-like functionalities such as commits, branches, switching between branches, and commit logs.

This project simulates a distributed system with support for multiple servers (via folders) and offers an interactive CLI experience for all repository operations.

---

## README

### Overview

The system aims to provide:
- Tree-structured, file-based storage for large CSV datasets
- Efficient branching and versioning
- Commit history and logging
- Hash-based data integrity using Merkle Trees
- Minimal data transfer for updates or corrections

### Key Features

#### 1. Initialize Repository
```bash
init <filename>
