﻿using System;
using System.Collections.Generic;
using System.Text;

namespace PortableNoise.Engine
{
    public class CrytoEngine
    {

        static public Blake2s CreateBlake2s(CrytoEngineType engineType)
        {
            return new InProject.InProjectBlake2s();
        }
    }
}
