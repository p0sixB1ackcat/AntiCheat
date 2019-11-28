#pragma once

#include <fstream>
#include <string>
#include <any>
#include <regex>
#include <algorithm>
#include "Shlwapi.h"

extern int g_globalKey;

extern int g_aimEnabled;
extern int g_aimKey;
extern int g_aimBone;
extern float g_aimFov;
extern float g_aimSmooth;
extern int g_aimDelay;
extern int g_aimRCS;

class setting {
public:
	setting(const char* words) {
		nameSpace = words;
		loadSettings();
	}

	std::string nameSpace;
	std::vector<std::string> names;
	std::vector<std::string> values;


	void loadSettings();
    
	template <class T>
	T get(const char * name);
};

void loadSettings();
void loadwhitelist(char** pWhiteList);