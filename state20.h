/* 
 *  generation of state files v20
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
 *  Copyright (C) 2009-2010 Zhenkai Liang <liangzk@comp.nus.edu.sg>
 *  Copyright (C) 2009-2010 Heng Yin <heyin@syr.edu>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _STATE_H_
#define _STATE_H_

#include "DECAF_main.h"

/* Whether to save registers in addition to memory */
#define SAVE_REGISTERS 1

/* In the current state file format, the layout of the x86 registers
   we use is modeled after 32-bit Linux's user_regs_struct. It's not
   really ideal for our applications: for instance, it records the
   segment registers, but not the LDT/GDT or the segment descriptors.
   The question of what registers we want to save should be revisited
   the next time we revise the file format. -SMcC */

struct state_file_regs_struct
{
  long int ebx;
  long int ecx;
  long int edx;
  long int esi;
  long int edi;
  long int ebp;
  long int eax;
  long int xds;
  long int xes;
  long int xfs;
  long int xgs;
  long int orig_eax;
  long int eip;
  long int xcs;
  long int eflags;
  long int esp;
  long int xss;
};

/* Whether to save kernel memory in addition to user memory */
#define SAVE_KERNEL_MEM 0

/* Saves memory state for process identified by cr3 into filename
   The state is captured at function call
   Returns zero if successful, otherwise it failed
*/
int save_state_by_cr3(uint32_t cr3, const char *filename);

/* Saves memory state for process identified by pid into filename
   The state is captured at function call
   Returns zero if successful, otherwise it failed
*/
int save_state_by_pid(uint32_t pid, const char *filename);

/* Saves memory state for process identified by cr3 into filename
   The state is captured the first time the process execution reaches addr
   Returns zero if successful, otherwise it failed
*/
int save_state_at_addr(uint32_t pid, uint32_t addr, const char *filename);

#endif // _STATE_H_
