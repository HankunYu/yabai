#ifndef SPACE_ANIMATION_H
#define SPACE_ANIMATION_H

struct space_animation;

bool space_animation_is_in_progress(void);
struct space_animation *space_animation_create(uint32_t did, uint64_t cur_sid, uint64_t new_sid, float direction, float duration, int easing);
void space_animation_run(struct space_animation *animation);
void space_animation_destroy(struct space_animation *animation);

#endif
