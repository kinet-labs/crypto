// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Translation unit for batch inversion + windowed G table + pipeline routines.
// All function bodies are header-inline; this file exists so the build system
// has a non-empty .cpp to feed into the static library.

#include "batch_inv.hpp"
#include "windowed_g_table.hpp"
#include "ecrecover_pipeline.hpp"
