/* 
 *  functionality to update instruction operands
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
 *  Copyright (C) 2009-2010 Zhenkai Liang <liangzk@comp.nus.edu.sg>
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

#include <sys/time.h>
#include <assert.h>
#include "operandinfo.h"
#include "config.h"
#include "tfd.h"
#include "DECAF_main.h"
#ifdef TAINT_ENABLED
#include "shared/tainting/taintcheck_opt.h"
#endif

/* Flag that states if tainted data has already been seen during trace */
int received_tainted_data = 0;



/* Copy the given taint record into the given operand
     and check whether this is the first tainted operand seen
*/
inline void record_taint_value(OperandVal * op) {
  struct timeval ftime;

  if (0 == received_tainted_data) {
    received_tainted_data = 1;
    if (gettimeofday(&ftime, 0) == 0) {
      monitor_printf(default_mon, "Time of first tainted data: %ld.%ld\n",
        ftime.tv_sec, ftime.tv_usec);
    }

  }

}

/* Given an operand, check taint information and store it */
void set_operand_taint(OperandVal *op) {
#ifdef TAINT_ENABLED
  switch (op->type) {
    case TRegister: {
      int regnum = REGNUM(op->addr.reg_addr);
      int offset = getOperandOffset(op);
      if(regnum!=-1)
        op->tainted = (uint16_t) 
          taintcheck_register_check(regnum, offset, op->length,cpu_single_env);
      break;
    }
    case TMemLoc: {
      op->tainted = taintcheck_check_virtmem(op->addr.mem32_addr, op->length);
      break;
    }
    default:
      op->tainted = 0;
      break;
  }

  if (op->tainted) {
    insn_tainted=1;
    record_taint_value(op);
  }
#else
  op->tainted = 0;
#endif // #ifdef TAINT_ENABLED
}

