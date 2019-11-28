
#include "pch.h"

#include "FileIni.h"

int getVKcode(const char* keyName) {
	//only works for F1 - F24
	int numberOnly = std::stoi(keyName + 1);
	return numberOnly + 0x6F;
}

void loadSettings() {

	setting settings("whitelist");
    for (int i = 0; i < settings.values.size(); ++i)
    {

    }
}

void loadwhitelist(char **pWhiteList)
{
    int i;
    setting whitelist("whitelist");
    if (*pWhiteList)
    {
        free(*pWhiteList);
        *pWhiteList = NULL;
    }

    *pWhiteList = (char*)malloc(0x1000);
    memset(*pWhiteList, 0x00, 0x1000);
    char* pMove = *pWhiteList;
    i = 0;

    while (1)
    {
        memcpy(pMove, whitelist.values[i].data(), whitelist.values[i].length());
        pMove += whitelist.values[i].length();
        if (i >= whitelist.values.size() - 1)
            break;
        *pMove = ',';
        ++pMove;
        ++i;
    }

}

template <class T>
T setting::get(const char * name) {
	std::string foundValue = "NotFound";

	int i = 0;
	for (; i < names.size(); i++) {
		if (names[i].find(name) != -1)
			foundValue = values[i];
	}

	if (foundValue.find("NotFound") != -1)
		return NULL;

	if  constexpr (std::is_floating_point<T>::value) {
		return std::stof(foundValue);
	}

	if constexpr (std::is_integral<T>::value) {
		return std::stoi(foundValue);
	}
	if constexpr (std::is_pointer<T>::value) {
		return values[i - 1].c_str();
	}

	return NULL;
}

void setting::loadSettings() {
	std::ifstream configFile;
	configFile.open("achievements_log.txt");
	if (!configFile) {
		MessageBoxA(0, "Could not find settings file", "ERROR", MB_OK);
		return;
	}
	bool correctNamespace = false;

	std::string line;
	while (getline(configFile, line)) {
		static std::string currentNameSpace = "";

		// get namespace
		int pos1 = line.find('[');
		int pos2 = line.find(']');

		if ((pos1 != -1) & (pos2 != -1)) {
			currentNameSpace = line.substr(pos1 + 1, (pos2 - pos1 - 1));
			//std::cout << "Current: " << line.substr(pos1 + 1, (pos2 - pos1 - 1)) << std::endl;
			if (currentNameSpace.find(nameSpace) != -1)
				correctNamespace = true;
			else
				correctNamespace = false;
			continue;
		}
		// 

		if (!correctNamespace)
			continue;

		// get a setting
		int settingPos = line.find('=');
		if (settingPos != -1) {
			std::string settingName = line.substr(0, settingPos);
			//std::cout << "Name: " << settingName << std::endl;

			std::string secondPart = line.substr(settingPos + 1, line.size() - 1);

			std::smatch m;
			std::regex e("[a-zA-Z0-9.]+");
			std::regex_search(secondPart, m, e);
			//std::cout << "Value: " << m.str(0) << std::endl;

			names.push_back(settingName);
			values.push_back(m.str(0));
		}
		//

	}
}
