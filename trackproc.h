/* 
 *  process tracking
 *
 *  Copyright (C) 2009-2013 Juan Caballero <juan.caballero@imdea.org>
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

#ifndef _TC_TRACKPROC_H_
#define _TC_TRACKPROC_H_
#include "shared/procmod.h"

#define MAX_CHILDPROC (10)

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* Start process tracking */
void trackproc_start(uint32_t pid);

/* Stop process tracking */
void trackproc_stop(void);

/* Get PID of root */
uint32_t trackproc_get_root_pid(void);

/* Check if process tracking has started */
int trackproc_is_running(void);

/* Get PID of current process */
uint32_t trackproc_get_current_pid(void);

/* Find index for given process handle */
int trackproc_find_handle(uint32_t uiHandle);

/* Find index for given process PID */
int trackproc_find_pid(uint32_t uiPID);

/* Add a new process handle to the array */
int trackproc_add_new_handle(uint32_t uiHandle, uint32_t uiParentPID);

/* Set PID of process with given handle to given PID */
void trackproc_set_pid(uint32_t uiHandle, uint32_t uiPID);

/* Get parent PID for given process (identified by PID) */
uint32_t trackproc_get_parent_pid(uint32_t uiPID);

/* Check if some child was found */
unsigned int trackproc_found_child(void);

/* Get process information for tracked processes */
procinfo_t *trackproc_get_tracked_processes_info(
  uint32_t tracked_pid, uint32_t *num_tracked_proc);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //_TC_TRACKPROC_H_
