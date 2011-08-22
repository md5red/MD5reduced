#include "Main.h"
#include <iostream>
#include <boost/thread.hpp> 
#include "Package.h"

using namespace std;


CPackage::CPackage(CCharset *forCharset)
{
	Initialize(forCharset);
}

CPackage::~CPackage()
{
}

Split_t *CPackage::GetPackage(const int forThread)
{
	return &(m_vSplitted[forThread]);
}

void CPackage::Initialize(CCharset *forCharset)
{
	double size = static_cast<double>(forCharset->GetLen());

	// Go.
	for (unsigned int i = 0; i < boost::thread::hardware_concurrency(); i++) {
		// Init.
		Split_t split;

		// Calc.
		split.firstChar = (i == 0) ? (int)(size / boost::thread::hardware_concurrency() * i) : (int)(size / boost::thread::hardware_concurrency() * i + 1);
		split.lastChar = (int)(size / boost::thread::hardware_concurrency() * (i + 1));
		if (split.lastChar > (forCharset->GetLen() - 1))
			split.lastChar = (int)(forCharset->GetLen() - 1);

		// Save.
		m_vSplitted.push_back(split);
	}
}