/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#define BUF_SIZE_MAP_NS 256

typedef struct bpf_map_def
{
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

enum bpf_pin_type
{
	PIN_NONE = 0,
	PIN_OBJECT_NS,
	PIN_GLOBAL_NS,
	PIN_CUSTOM_NS,
};
