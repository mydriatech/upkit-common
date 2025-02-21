/*
    Copyright 2025 MydriaTech AB

    Licensed under the Apache License 2.0 with Free world makers exception
    1.0.0 (the "License"); you may not use this file except in compliance with
    the License. You should have obtained a copy of the License with the source
    or binary distribution in file named

        LICENSE-Apache-2.0-with-FWM-Exception-1.0.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

//! Automagic enum snake_case naming and lookup.

use crossbeam_skiplist::SkipMap;
use serde::Serialize;
use strum::IntoEnumIterator;

pub struct NamedEnum<T> {
    enum_by_name: SkipMap<String, T>,
    name_by_enum: SkipMap<T, String>,
}

impl<T: Serialize + Clone + Ord + PartialOrd + Send + IntoEnumIterator + 'static> Default
    for NamedEnum<T>
{
    fn default() -> Self {
        let ret = Self {
            enum_by_name: SkipMap::default(),
            name_by_enum: SkipMap::default(),
        };
        for t in T::iter() {
            let name = serde_variant::to_variant_name::<T>(&t).unwrap();
            ret.enum_by_name.insert(name.to_string(), t.clone());
            ret.name_by_enum.insert(t.clone(), name.to_string());
        }
        ret
    }
}

impl<T: Serialize + Clone + Ord + PartialOrd> NamedEnum<T> {
    /// Convert to a recognizable label
    pub fn to_name(&self, t: &T) -> String {
        self.name_by_enum
            .get(t)
            .map(|entry| entry.value().to_owned())
            .unwrap()
    }

    /// Convert to a recognizable label
    pub fn by_name(&self, name: &str) -> Option<T> {
        self.enum_by_name
            .get(name)
            .map(|entry| entry.value().to_owned())
    }
}
