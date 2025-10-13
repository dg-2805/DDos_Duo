#ifndef HEALTH_CHECKER_H
#define HEALTH_CHECKER_H

// Function prototypes
int health_checker_init(int check_interval_ms);
void health_checker_stop(void);
int health_checker_is_running(void);

#endif // HEALTH_CHECKER_H
